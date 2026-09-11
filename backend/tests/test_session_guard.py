"""Tests for LLM Tripwire Session Guard (Session Threat Tracking)."""

from concurrent.futures import ThreadPoolExecutor
import pytest

from app.security.session_guard import (
    RiskLevel,
    calculate_risk_level,
    clear_sessions,
    get_or_create_session,
    record_event,
)


@pytest.fixture(autouse=True)
def reset_session_tracker():
    """Ensure clean session state for every test."""
    clear_sessions()
    yield
    clear_sessions()


def test_new_session_starts_at_low():
    """A newly initialized session starts with 0 score, 0 requests, and LOW risk."""
    session = get_or_create_session("session-test-01")
    assert session.session_id == "session-test-01"
    assert session.cumulative_score == 0
    assert session.request_count == 0
    assert session.blocked_count == 0
    assert session.last_action is None
    assert session.threat_types_seen == []
    assert session.risk_level == RiskLevel.LOW.value


def test_repeated_suspicious_events_increase_cumulative_score():
    """Repeated suspicious requests accumulate risk over time."""
    session_id = "session-test-02"

    # Event 1: moderate suspicion
    state_1 = record_event(session_id, threat_score=30, action="MONITOR", threat_types=["confidential_data_extraction"])
    assert state_1.cumulative_score == 30
    assert state_1.request_count == 1
    assert state_1.blocked_count == 0
    assert state_1.risk_level == RiskLevel.GUARDED.value

    # Event 2: additional suspicious activity
    state_2 = record_event(session_id, threat_score=30, action="MONITOR", threat_types=["confidential_data_extraction"])
    assert state_2.cumulative_score == 60
    assert state_2.request_count == 2
    assert state_2.blocked_count == 0
    assert state_2.risk_level == RiskLevel.HIGH.value


def test_score_is_capped_at_100():
    """Cumulative threat score must never exceed the ceiling of 100."""
    session_id = "session-test-03"

    # Two heavy attacks of 85 points each
    record_event(session_id, threat_score=85, action="BLOCK", threat_types=["prompt_injection"])
    state_after = record_event(session_id, threat_score=85, action="BLOCK", threat_types=["prompt_injection"])

    assert state_after.cumulative_score == 100
    assert state_after.risk_level == RiskLevel.CRITICAL.value


def test_distinct_threat_types_are_tracked():
    """Session tracks unique threat types seen without duplicating entries."""
    session_id = "session-test-04"

    record_event(session_id, threat_score=40, action="MONITOR", threat_types=["prompt_injection"])
    record_event(session_id, threat_score=40, action="MONITOR", threat_types=["prompt_injection", "source_code_extraction"])
    record_event(session_id, threat_score=30, action="MONITOR", threat_types=["confidential_data_extraction", "prompt_injection"])

    state = get_or_create_session(session_id)
    assert len(state.threat_types_seen) == 3
    assert "prompt_injection" in state.threat_types_seen
    assert "source_code_extraction" in state.threat_types_seen
    assert "confidential_data_extraction" in state.threat_types_seen


def test_blocked_count_increments_correctly():
    """Blocked count increments only when action is BLOCK, while total requests increment always."""
    session_id = "session-test-05"

    record_event(session_id, threat_score=0, action="ALLOW", threat_types=[])
    record_event(session_id, threat_score=30, action="MONITOR", threat_types=["confidential_data_extraction"])
    record_event(session_id, threat_score=85, action="BLOCK", threat_types=["prompt_injection"])
    record_event(session_id, threat_score=90, action="BLOCK", threat_types=["source_code_extraction"])

    state = get_or_create_session(session_id)
    assert state.request_count == 4
    assert state.blocked_count == 2
    assert state.last_action == "BLOCK"


def test_risk_levels_transition_correctly():
    """Risk levels accurately map across 0-24 (LOW), 25-49 (GUARDED), 50-74 (HIGH), 75-100 (CRITICAL)."""
    assert calculate_risk_level(0) == "LOW"
    assert calculate_risk_level(24) == "LOW"
    assert calculate_risk_level(25) == "GUARDED"
    assert calculate_risk_level(49) == "GUARDED"
    assert calculate_risk_level(50) == "HIGH"
    assert calculate_risk_level(74) == "HIGH"
    assert calculate_risk_level(75) == "CRITICAL"
    assert calculate_risk_level(100) == "CRITICAL"

    session_id = "session-test-06"
    assert record_event(session_id, 10, "ALLOW", []).risk_level == "LOW"
    assert record_event(session_id, 20, "MONITOR", []).risk_level == "GUARDED"   # score: 30
    assert record_event(session_id, 25, "MONITOR", []).risk_level == "HIGH"      # score: 55
    assert record_event(session_id, 25, "MONITOR", []).risk_level == "CRITICAL"  # score: 80


def test_separate_sessions_do_not_share_state():
    """Independent sessions maintain completely isolated threat metrics."""
    record_event("client-alice", threat_score=85, action="BLOCK", threat_types=["prompt_injection"])
    record_event("client-bob", threat_score=0, action="ALLOW", threat_types=[])

    alice_state = get_or_create_session("client-alice")
    bob_state = get_or_create_session("client-bob")

    assert alice_state.cumulative_score == 85
    assert alice_state.blocked_count == 1
    assert alice_state.risk_level == "CRITICAL"
    assert alice_state.threat_types_seen == ["prompt_injection"]

    assert bob_state.cumulative_score == 0
    assert bob_state.blocked_count == 0
    assert bob_state.risk_level == "LOW"
    assert bob_state.threat_types_seen == []


def test_concurrent_thread_safe_access():
    """Multi-threaded concurrent event recordings update session state without race conditions."""
    session_id = "concurrent-session"

    def record_single_event(i: int):
        record_event(
            session_id=session_id,
            threat_score=1,
            action="BLOCK" if i % 2 == 0 else "ALLOW",
            threat_types=[f"threat_{i % 3}"],
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(record_single_event, range(50)))

    final_state = get_or_create_session(session_id)
    assert final_state.request_count == 50
    assert final_state.blocked_count == 25
    assert final_state.cumulative_score == 50
    assert final_state.risk_level == "HIGH"
    assert sorted(final_state.threat_types_seen) == ["threat_0", "threat_1", "threat_2"]
