"""SQLite-backed telemetry and security event store for LLM Tripwire SOC monitoring."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import threading
import uuid
from typing import Any, Dict, List, Optional

# Default database location inside backend root, configurable via environment
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = os.environ.get("TRIPWIRE_DB_PATH", str(BASE_DIR / "tripwire_telemetry.db"))


class TelemetryStore:
    """Thread-safe SQLite-backed security event store."""

    def __init__(self, db_path: Optional[str] = None, max_capacity: int = 1000):
        self.db_path = str(db_path) if db_path is not None else DEFAULT_DB_PATH
        self._max_capacity = max_capacity
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Creates a thread-safe connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes tables and indices if they do not exist."""
        if self.db_path != ":memory:":
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        with self._lock:
            with self._get_connection() as conn:
                if self.db_path != ":memory:":
                    try:
                        conn.execute("PRAGMA journal_mode=WAL;")
                        conn.execute("PRAGMA synchronous=NORMAL;")
                    except sqlite3.OperationalError:
                        pass

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS telemetry_events (
                        id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        attack_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        threat_score INTEGER NOT NULL,
                        enforcement_action TEXT NOT NULL,
                        matched_signals TEXT NOT NULL,
                        cumulative_session_score INTEGER NOT NULL
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events (timestamp DESC);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_session ON telemetry_events (session_id);")
                conn.commit()

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
        """Records a new security telemetry event into persistent SQLite storage."""
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        eid = event_id or f"evt_{uuid.uuid4().hex[:12]}"
        signals_list = list(matched_signals) if matched_signals is not None else []
        signals_json = json.dumps(signals_list)

        event = {
            "id": eid,
            "session_id": session_id,
            "timestamp": timestamp,
            "attack_type": attack_type,
            "severity": severity.upper(),
            "threat_score": int(threat_score),
            "enforcement_action": enforcement_action.upper(),
            "matched_signals": signals_list,
            "cumulative_session_score": int(cumulative_session_score),
        }

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO telemetry_events (
                        id, session_id, timestamp, attack_type, severity,
                        threat_score, enforcement_action, matched_signals, cumulative_session_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event["id"],
                        event["session_id"],
                        event["timestamp"],
                        event["attack_type"],
                        event["severity"],
                        event["threat_score"],
                        event["enforcement_action"],
                        signals_json,
                        event["cumulative_session_score"],
                    ),
                )
                if self._max_capacity and self._max_capacity > 0:
                    conn.execute(
                        """
                        DELETE FROM telemetry_events
                        WHERE rowid NOT IN (
                            SELECT rowid FROM telemetry_events ORDER BY rowid DESC LIMIT ?
                        )
                        """,
                        (self._max_capacity,),
                    )
                conn.commit()

        return event

    def get_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Returns all recorded events, ordered newest first."""
        query = """
            SELECT id, session_id, timestamp, attack_type, severity,
                   threat_score, enforcement_action, matched_signals, cumulative_session_score
            FROM telemetry_events
            ORDER BY rowid DESC
        """
        params = ()
        if limit is not None and limit > 0:
            query += " LIMIT ?"
            params = (int(limit),)

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

        events = []
        for row in rows:
            try:
                signals = json.loads(row["matched_signals"])
            except (json.JSONDecodeError, TypeError):
                signals = []

            events.append({
                "id": row["id"],
                "session_id": row["session_id"],
                "timestamp": row["timestamp"],
                "attack_type": row["attack_type"],
                "severity": row["severity"],
                "threat_score": row["threat_score"],
                "enforcement_action": row["enforcement_action"],
                "matched_signals": signals,
                "cumulative_session_score": row["cumulative_session_score"],
            })
        return events

    def count(self) -> int:
        """Returns the total number of events recorded in the database."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM telemetry_events")
                row = cursor.fetchone()
                return row[0] if row else 0

    def clear(self) -> None:
        """Clears all stored events from the database (used in tests and resets)."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM telemetry_events")
                conn.commit()


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
