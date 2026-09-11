import re
import uuid
from typing import List, Optional
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.security.input_guard import Action, analyze_input
from app.security.output_guard import OutputAction, analyze_output
from app.security.policy_engine import PolicyAction, evaluate_session_policy
from app.security.session_guard import get_or_create_session, record_event
from app.security.stream_guard import StreamGuard
from app.security.telemetry import classify_attack_type, record_telemetry_event
from app.services.llm_service import get_mock_llm

router = APIRouter()


def _fragment_stream(text: str) -> List[str]:
    """Splits raw response text into streaming token fragments for incremental inspection."""
    if not text:
        return []
    parts = re.findall(r"\S+\s*|\n+", text)
    return parts if parts else [text]


class ChatRequest(BaseModel):
    """Chat request payload schema."""
    query: str
    session_id: Optional[str] = None


@router.post("/chat")
def chat_endpoint(request: ChatRequest):
    """LLM Tripwire defensive runtime security gateway.

    Pipeline:
    1. Session Resolution: Use provided session_id or generate a new unique identifier.
    2. Session Policy Enforcement: Evaluate pre-existing session risk state.
       - If session policy is BLOCK (CRITICAL accumulated risk): Block immediately BEFORE calling AI.
    3. Input Guard: Inspect user query using analyze_input().
       - If input BLOCK: return HTTP 403 immediately; NEVER call the enterprise AI.
    4. Enterprise AI: Call MockEnterpriseLLM for allowed/monitored queries.
    5. Output Guard: Inspect AI response using analyze_output().
       - If output BLOCK: Redact output and return safe notification; never expose raw sensitive data.
       - If ALLOW / MONITOR: Return original response with full audit metadata.
    6. Return complete input, output, session, and policy enforcement audit state.
    """
    # 1. Resolve Session ID
    session_id = (
        request.session_id.strip()
        if request.session_id and request.session_id.strip()
        else f"sess_{uuid.uuid4().hex[:12]}"
    )

    # 2. Session Policy Enforcement (Evaluates accumulated risk from prior requests)
    prior_session = get_or_create_session(session_id)
    session_policy_decision = evaluate_session_policy(prior_session)

    if session_policy_decision == PolicyAction.BLOCK.value:
        # Session has reached CRITICAL accumulated risk from prior requests.
        session_state = record_event(
            session_id=session_id,
            threat_score=0,
            action="BLOCK",
            threat_types=["session_policy_block"],
            increment_request_count=True,
        )
        record_telemetry_event(
            session_id=session_id,
            attack_type="session_policy_block",
            severity="CRITICAL",
            threat_score=100,
            enforcement_action="BLOCK",
            matched_signals=["session_risk_critical_policy_enforcement"],
            cumulative_session_score=session_state.cumulative_score,
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "blocked": True,
                "threat_score": 100,
                "action": "BLOCK",
                "threat_types": ["session_policy_block"],
                "matched_signals": ["session_risk_critical_policy_enforcement"],
                "response": "Response blocked by LLM Tripwire: session has been blocked due to accumulated security risk.",
                "output_blocked": False,
                "output_threat_score": 0,
                "output_action": None,
                "leak_types": [],
                "output_matched_signals": [],
                "session_id": session_state.session_id,
                "cumulative_score": session_state.cumulative_score,
                "request_count": session_state.request_count,
                "blocked_count": session_state.blocked_count,
                "risk_level": session_state.risk_level,
                "threat_types_seen": session_state.threat_types_seen,
                "session_policy_action": session_policy_decision,
            },
        )

    # 3. Input Guard Inspection
    input_analysis = analyze_input(request.query)

    if input_analysis["action"] == Action.BLOCK.value:
        # Record input block event in session guard
        session_state = record_event(
            session_id=session_id,
            threat_score=input_analysis["threat_score"],
            action=input_analysis["action"],
            threat_types=input_analysis["threat_types"],
            increment_request_count=True,
        )
        attack_type = classify_attack_type(
            threat_types=input_analysis["threat_types"],
            matched_signals=input_analysis["matched_signals"],
            default="prompt_injection",
        )
        record_telemetry_event(
            session_id=session_id,
            attack_type=attack_type,
            severity="CRITICAL",
            threat_score=input_analysis["threat_score"],
            enforcement_action="BLOCK",
            matched_signals=input_analysis["matched_signals"],
            cumulative_session_score=session_state.cumulative_score,
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "blocked": True,
                "threat_score": input_analysis["threat_score"],
                "action": input_analysis["action"],
                "threat_types": input_analysis["threat_types"],
                "matched_signals": input_analysis["matched_signals"],
                "response": None,
                "output_blocked": False,
                "output_threat_score": 0,
                "output_action": None,
                "leak_types": [],
                "output_matched_signals": [],
                "session_id": session_state.session_id,
                "cumulative_score": session_state.cumulative_score,
                "request_count": session_state.request_count,
                "blocked_count": session_state.blocked_count,
                "risk_level": session_state.risk_level,
                "threat_types_seen": session_state.threat_types_seen,
                "session_policy_action": session_policy_decision,
            },
        )

    # Record input event for allowed / monitored request
    session_state = record_event(
        session_id=session_id,
        threat_score=input_analysis["threat_score"],
        action=input_analysis["action"],
        threat_types=input_analysis["threat_types"],
        increment_request_count=True,
    )

    # 4. Invoke Enterprise AI for non-blocked inputs
    llm = get_mock_llm()
    ai_raw_response = llm.query(request.query)

    # 5. Incremental Streaming Inspection via StreamGuard
    guard = StreamGuard()
    chunks = _fragment_stream(ai_raw_response)
    safe_chunks = list(guard.intercept(chunks))

    if guard.terminated:
        output_blocked = True
        output_analysis = guard.detection_details or analyze_output(guard.accumulated_text)
        final_response = "Response blocked by LLM Tripwire because sensitive information was detected."
    else:
        output_analysis = analyze_output(ai_raw_response)
        if output_analysis["action"] == OutputAction.BLOCK.value:
            output_blocked = True
            final_response = "Response blocked by LLM Tripwire because sensitive information was detected."
        elif output_analysis["action"] == OutputAction.INTERCEPT.value:
            output_blocked = True
            final_response = "Response intercepted by LLM Tripwire because sensitive content was detected."
        else:
            output_blocked = False
            final_response = ai_raw_response

    # Record output event in session guard
    session_state = record_event(
        session_id=session_id,
        threat_score=output_analysis["threat_score"],
        action=output_analysis["action"],
        threat_types=output_analysis["leak_types"],
        increment_request_count=False,
    )

    # Record Telemetry Event for requests reaching Output Guard / Stream Guard
    if guard.terminated:
        attack_type = classify_attack_type(
            threat_types=output_analysis.get("leak_types"),
            matched_signals=output_analysis.get("matched_signals"),
            default="stream_interception_leak",
        )
        record_telemetry_event(
            session_id=session_id,
            attack_type=attack_type,
            severity="CRITICAL",
            threat_score=output_analysis.get("threat_score", 100),
            enforcement_action="BLOCK",
            matched_signals=output_analysis.get("matched_signals", ["stream_interception_leak_detected"]),
            cumulative_session_score=session_state.cumulative_score,
        )
    elif output_analysis["action"] == OutputAction.BLOCK.value:
        attack_type = classify_attack_type(
            threat_types=output_analysis.get("leak_types"),
            matched_signals=output_analysis.get("matched_signals"),
            default="confidential_data_extraction",
        )
        record_telemetry_event(
            session_id=session_id,
            attack_type=attack_type,
            severity="CRITICAL",
            threat_score=output_analysis["threat_score"],
            enforcement_action="BLOCK",
            matched_signals=output_analysis.get("matched_signals", []),
            cumulative_session_score=session_state.cumulative_score,
        )
    elif output_analysis["action"] == OutputAction.INTERCEPT.value:
        attack_type = classify_attack_type(
            threat_types=output_analysis.get("leak_types"),
            matched_signals=output_analysis.get("matched_signals"),
            default="confidential_data_extraction",
        )
        record_telemetry_event(
            session_id=session_id,
            attack_type=attack_type,
            severity="HIGH",
            threat_score=output_analysis["threat_score"],
            enforcement_action="INTERCEPT",
            matched_signals=output_analysis.get("matched_signals", []),
            cumulative_session_score=session_state.cumulative_score,
        )
    elif input_analysis["action"] == Action.MONITOR.value or output_analysis["action"] == OutputAction.MONITOR.value:
        combined_types = input_analysis["threat_types"] + output_analysis.get("leak_types", [])
        combined_signals = input_analysis["matched_signals"] + output_analysis.get("matched_signals", [])
        attack_type = classify_attack_type(
            threat_types=combined_types,
            matched_signals=combined_signals,
            default="monitored_activity",
        )
        record_telemetry_event(
            session_id=session_id,
            attack_type=attack_type,
            severity="MEDIUM",
            threat_score=max(input_analysis["threat_score"], output_analysis["threat_score"]),
            enforcement_action="MONITOR",
            matched_signals=combined_signals,
            cumulative_session_score=session_state.cumulative_score,
        )
    else:
        record_telemetry_event(
            session_id=session_id,
            attack_type="benign_query",
            severity="LOW",
            threat_score=0,
            enforcement_action="ALLOW",
            matched_signals=[],
            cumulative_session_score=session_state.cumulative_score,
        )

    return {
        "blocked": False,
        "threat_score": input_analysis["threat_score"],
        "action": input_analysis["action"],
        "threat_types": input_analysis["threat_types"],
        "matched_signals": input_analysis["matched_signals"],
        "response": final_response,
        "output_blocked": output_blocked,
        "output_threat_score": output_analysis["threat_score"],
        "output_action": output_analysis["action"],
        "leak_types": output_analysis["leak_types"],
        "output_matched_signals": output_analysis["matched_signals"],
        "stream_terminated": guard.terminated,
        "session_id": session_state.session_id,
        "cumulative_score": session_state.cumulative_score,
        "request_count": session_state.request_count,
        "blocked_count": session_state.blocked_count,
        "risk_level": session_state.risk_level,
        "threat_types_seen": session_state.threat_types_seen,
        "session_policy_action": session_policy_decision,
    }

