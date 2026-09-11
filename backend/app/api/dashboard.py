"""Security Dashboard API router for LLM Tripwire."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query

from app.security.session_guard import get_all_sessions
from app.security.telemetry import get_telemetry_events

router = APIRouter()


def _classify_threat(threat: str) -> str:
    """Classifies a raw threat type into standard dashboard categories."""
    t = threat.lower()
    if "prompt_injection" in t or "instruction_override" in t:
        return "prompt_injection"
    if "system_prompt" in t:
        return "system_prompt_extraction"
    if "source_code" in t:
        return "source_code_extraction"
    if "confidential" in t or "titan" in t:
        return "confidential_data_extraction"
    return "other"


def _compute_dashboard_metrics() -> Dict[str, Any]:
    """Aggregates real-time SOC security overview metrics from Session Guard."""
    sessions = get_all_sessions()

    total_sessions = len(sessions)
    active_sessions = len(sessions)
    total_requests = sum(s.request_count for s in sessions)
    total_blocked = sum(s.blocked_count for s in sessions)

    critical_sessions = sum(1 for s in sessions if s.risk_level.upper() == "CRITICAL")
    high_risk_sessions = sum(1 for s in sessions if s.risk_level.upper() == "HIGH")
    monitored_sessions = sum(
        1 for s in sessions
        if (s.risk_level.upper() == "GUARDED" or s.last_action == "MONITOR")
        and s.risk_level.upper() not in ("CRITICAL", "HIGH")
    )

    threat_distribution = {
        "prompt_injection": 0,
        "system_prompt_extraction": 0,
        "source_code_extraction": 0,
        "confidential_data_extraction": 0,
        "other": 0,
    }

    for s in sessions:
        for threat in s.threat_types_seen:
            category = _classify_threat(threat)
            threat_distribution[category] += 1

    return {
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "critical_sessions": critical_sessions,
        "high_risk_sessions": high_risk_sessions,
        "monitored_sessions": monitored_sessions,
        "threat_distribution": threat_distribution,
    }


@router.get("/dashboard/overview")
def get_dashboard_overview() -> Dict[str, Any]:
    """Returns real-time SOC security overview metrics."""
    return _compute_dashboard_metrics()


@router.get("/dashboard/summary")
def get_dashboard_summary() -> Dict[str, Any]:
    """Backward-compatible alias for /dashboard/overview."""
    return _compute_dashboard_metrics()


@router.get("/dashboard/events")
def get_dashboard_events(
    limit: Optional[int] = Query(None, description="Maximum number of newest events to return")
) -> List[Dict[str, Any]]:
    """Returns recorded security telemetry events, ordered newest first."""
    return get_telemetry_events(limit=limit)


@router.get("/dashboard/threat-distribution")
def get_dashboard_threat_distribution() -> Dict[str, int]:
    """Returns real-time threat distribution counts across all detected categories."""
    metrics = _compute_dashboard_metrics()
    return metrics["threat_distribution"]


@router.get("/dashboard/sessions")
def get_dashboard_sessions() -> List[Dict[str, Any]]:
    """Returns real-time session records from Session Guard.

    Exposes only telemetry fields:
    - session_id
    - cumulative_score
    - request_count
    - blocked_count
    - risk_level
    - last_action
    - threat_types_seen
    """
    sessions = get_all_sessions()
    return [
        {
            "session_id": s.session_id,
            "cumulative_score": s.cumulative_score,
            "request_count": s.request_count,
            "blocked_count": s.blocked_count,
            "risk_level": s.risk_level,
            "last_action": s.last_action,
            "threat_types_seen": s.threat_types_seen,
        }
        for s in sessions
    ]
