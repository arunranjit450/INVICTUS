"""In-memory telemetry and security event store for LLM Tripwire SOC monitoring."""

from datetime import datetime, timezone
import threading
import uuid
from typing import Any, Dict, List, Optional


class TelemetryStore:
    """Thread-safe in-memory security event store."""

    def __init__(self, max_capacity: int = 1000):
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._max_capacity = max_capacity

    def record_event(
        self,
        session_id: str,
        attack_type: str,
        severity: str,
        threat_score: int,
        enforcement_action: str,
        matched_signals: List[str],
        cumulative_session_score: int,
        timestamp: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records a new security telemetry event."""
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        event = {
            "id": event_id or f"evt_{uuid.uuid4().hex[:12]}",
            "session_id": session_id,
            "timestamp": timestamp,
            "attack_type": attack_type,
            "severity": severity.upper(),
            "threat_score": int(threat_score),
            "enforcement_action": enforcement_action.upper(),
            "matched_signals": list(matched_signals),
            "cumulative_session_score": int(cumulative_session_score),
        }

        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_capacity:
                # Evict oldest events if exceeding capacity
                self._events = self._events[-self._max_capacity:]

        return event

    def get_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Returns all recorded events, ordered newest first."""
        with self._lock:
            events_copy = list(reversed(self._events))

        if limit is not None and limit > 0:
            return events_copy[:limit]
        return events_copy

    def count(self) -> int:
        """Returns the total number of events recorded."""
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        """Clears all stored events (used in tests)."""
        with self._lock:
            self._events.clear()


# Module-level singleton store
_telemetry_store = TelemetryStore()


def calculate_severity(score: int, action: str) -> str:
    """Derives a normalized severity level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')."""
    act = (action or "").upper()
    if act == "BLOCK" or score >= 75:
        return "CRITICAL"
    if act == "INTERCEPT" or score >= 50:
        return "HIGH"
    if act == "MONITOR" or score >= 25:
        return "MEDIUM"
    return "LOW"


def classify_attack_type(
    threat_types: Optional[List[str]] = None,
    matched_signals: Optional[List[str]] = None,
    default: str = "benign_query",
) -> str:
    """Extracts a primary attack/threat category label from signals or threat types."""
    types = [t.lower() for t in (threat_types or [])]
    signals = [s.lower() for s in (matched_signals or [])]

    # Priority-based attack classification
    for item in types + signals:
        if "canary" in item:
            return "canary_exposure"
        if "prompt_injection" in item or "instruction_override" in item:
            return "prompt_injection"
        if "system_prompt" in item:
            return "system_prompt_extraction"
        if "source_code" in item:
            return "source_code_extraction"
        if "confidential" in item or "project_titan" in item or "titan" in item:
            return "confidential_data_extraction"
        if "session_policy" in item:
            return "session_policy_block"
        if "secret" in item or "token" in item:
            return "secret_token_leakage"

    if types:
        return types[0]
    return default


def record_telemetry_event(
    session_id: str,
    attack_type: str,
    severity: str,
    threat_score: int,
    enforcement_action: str,
    matched_signals: List[str],
    cumulative_session_score: int,
    timestamp: Optional[str] = None,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Records an event in the singleton telemetry store."""
    return _telemetry_store.record_event(
        session_id=session_id,
        attack_type=attack_type,
        severity=severity,
        threat_score=threat_score,
        enforcement_action=enforcement_action,
        matched_signals=matched_signals,
        cumulative_session_score=cumulative_session_score,
        timestamp=timestamp,
        event_id=event_id,
    )


def get_telemetry_events(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieves all telemetry events, newest first."""
    return _telemetry_store.get_events(limit=limit)


def clear_telemetry_events() -> None:
    """Clears the singleton telemetry store."""
    _telemetry_store.clear()
