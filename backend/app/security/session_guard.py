"""Session Threat Tracker & State Guard for LLM Tripwire.

Maintains in-memory, thread-safe session state tracking cumulative risk scores,
distinct threat patterns, and blocked request counts across multi-turn interactions.
"""

import threading
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Session risk severity classification."""
    LOW = "LOW"
    GUARDED = "GUARDED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SessionState(BaseModel):
    """Represents the real-time security state of an active client session."""
    session_id: str
    cumulative_score: int = 0
    request_count: int = 0
    blocked_count: int = 0
    last_action: Optional[str] = None
    threat_types_seen: List[str] = Field(default_factory=list)
    risk_level: str = RiskLevel.LOW.value

    def to_dict(self) -> dict:
        """Serializes SessionState to a plain dictionary."""
        return self.model_dump()


def calculate_risk_level(cumulative_score: int) -> str:
    """Calculates risk level from cumulative score.

    Risk Levels:
    - 0–24: LOW
    - 25–49: GUARDED
    - 50–74: HIGH
    - 75–100: CRITICAL
    """
    if cumulative_score >= 75:
        return RiskLevel.CRITICAL.value
    if cumulative_score >= 50:
        return RiskLevel.HIGH.value
    if cumulative_score >= 25:
        return RiskLevel.GUARDED.value
    return RiskLevel.LOW.value


class SessionTracker:
    """Thread-safe in-memory session manager."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, SessionState] = {}

    def get_or_create_session(self, session_id: str) -> SessionState:
        """Retrieves an existing session state or initializes a new one at LOW risk."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id)
            # Return a copy to ensure thread safety for callers
            return self._sessions[session_id].model_copy(deep=True)

    def record_event(
        self,
        session_id: str,
        threat_score: int,
        action: str,
        threat_types: List[str],
        increment_request_count: bool = True,
    ) -> SessionState:
        """Records a security event, updating cumulative score, counts, and risk level.

        Args:
            session_id: Identifier for the client interaction session.
            threat_score: Score from 0 to 100 for this single event.
            action: Action taken (e.g. 'ALLOW', 'MONITOR', 'INTERCEPT', 'BLOCK').
            threat_types: Categories of threats detected in this event.
            increment_request_count: Whether to increment session.request_count.

        Returns:
            Updated SessionState.
        """
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id)

            session = self._sessions[session_id]

            # 1. Update cumulative score (capped between 0 and 100)
            if threat_score > 0:
                session.cumulative_score = min(100, max(0, session.cumulative_score + threat_score))

            # 2. Increment total request count
            if increment_request_count:
                session.request_count += 1

            # 3. Increment blocked request count if blocked
            if action.upper() == "BLOCK":
                session.blocked_count += 1

            # 4. Record last action
            session.last_action = action

            # 5. Track distinct threat types seen
            for t_type in threat_types:
                if t_type and t_type not in session.threat_types_seen:
                    session.threat_types_seen.append(t_type)

            # 6. Recalculate session risk level
            session.risk_level = calculate_risk_level(session.cumulative_score)

            return session.model_copy(deep=True)

    def clear(self) -> None:
        """Resets all tracked sessions (used in test isolation)."""
        with self._lock:
            self._sessions.clear()


# Global in-memory singleton tracker instance
_tracker = SessionTracker()


def get_or_create_session(session_id: str) -> SessionState:
    """Thread-safe function to retrieve or create a SessionState."""
    return _tracker.get_or_create_session(session_id)


def record_event(
    session_id: str,
    threat_score: int,
    action: str,
    threat_types: List[str],
    increment_request_count: bool = True,
) -> SessionState:
    """Thread-safe function to record a security event for a session."""
    return _tracker.record_event(
        session_id=session_id,
        threat_score=threat_score,
        action=action,
        threat_types=threat_types,
        increment_request_count=increment_request_count,
    )


def clear_sessions() -> None:
    """Clears all in-memory session states."""
    _tracker.clear()
