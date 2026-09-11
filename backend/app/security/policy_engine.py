"""Session Policy Enforcement Engine for LLM Tripwire.

Evaluates accumulated session risk state to determine runtime gateway enforcement actions
(ALLOW, MONITOR, INTERCEPT, BLOCK) for subsequent request processing.
"""

from enum import Enum
from typing import Union

from app.security.session_guard import RiskLevel, SessionState


class PolicyAction(str, Enum):
    """Enforcement policy actions."""
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    INTERCEPT = "INTERCEPT"
    BLOCK = "BLOCK"


def evaluate_session_policy(session: Union[SessionState, str]) -> str:
    """Evaluates session risk level to determine policy enforcement action.

    Deterministic Policy:
    - LOW risk -> ALLOW
    - GUARDED risk -> MONITOR
    - HIGH risk -> INTERCEPT
    - CRITICAL risk -> BLOCK

    Args:
        session: Either a SessionState instance or a risk level string.

    Returns:
        One of 'ALLOW', 'MONITOR', 'INTERCEPT', 'BLOCK'.
    """
    if isinstance(session, str):
        risk_level = session.upper()
    elif isinstance(session, SessionState):
        risk_level = session.risk_level.upper()
    else:
        risk_level = str(getattr(session, "risk_level", "LOW")).upper()

    if risk_level == RiskLevel.CRITICAL.value:
        return PolicyAction.BLOCK.value
    if risk_level == RiskLevel.HIGH.value:
        return PolicyAction.INTERCEPT.value
    if risk_level == RiskLevel.GUARDED.value:
        return PolicyAction.MONITOR.value
    return PolicyAction.ALLOW.value
