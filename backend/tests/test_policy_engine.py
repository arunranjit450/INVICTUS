"""Tests for LLM Tripwire Session Policy Engine."""

from app.security.policy_engine import PolicyAction, evaluate_session_policy
from app.security.session_guard import RiskLevel, SessionState


def test_low_risk_session_policy_allow():
    """A session with LOW risk level evaluates to ALLOW."""
    session = SessionState(session_id="test-low", cumulative_score=0, risk_level=RiskLevel.LOW.value)
    decision = evaluate_session_policy(session)
    assert decision == PolicyAction.ALLOW.value


def test_guarded_risk_session_policy_monitor():
    """A session with GUARDED risk level evaluates to MONITOR."""
    session = SessionState(session_id="test-guarded", cumulative_score=35, risk_level=RiskLevel.GUARDED.value)
    decision = evaluate_session_policy(session)
    assert decision == PolicyAction.MONITOR.value


def test_high_risk_session_policy_intercept():
    """A session with HIGH risk level evaluates to INTERCEPT."""
    session = SessionState(session_id="test-high", cumulative_score=60, risk_level=RiskLevel.HIGH.value)
    decision = evaluate_session_policy(session)
    assert decision == PolicyAction.INTERCEPT.value


def test_critical_risk_session_policy_block():
    """A session with CRITICAL risk level evaluates to BLOCK."""
    session = SessionState(session_id="test-critical", cumulative_score=85, risk_level=RiskLevel.CRITICAL.value)
    decision = evaluate_session_policy(session)
    assert decision == PolicyAction.BLOCK.value


def test_policy_with_string_risk_levels():
    """Policy engine accepts raw risk level strings directly."""
    assert evaluate_session_policy("LOW") == "ALLOW"
    assert evaluate_session_policy("GUARDED") == "MONITOR"
    assert evaluate_session_policy("HIGH") == "INTERCEPT"
    assert evaluate_session_policy("CRITICAL") == "BLOCK"
