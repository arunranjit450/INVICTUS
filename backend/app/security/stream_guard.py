"""Streaming Output Interceptor & Real-Time Data Leakage Guard for LLM Tripwire.

Provides deterministic, incremental inspection for streaming AI and RAG responses.
Inspects accumulated text as chunks arrive, terminating the stream immediately
if a sensitive leak, confidential document reference, proprietary code, or canary token
is detected, while guaranteeing that malicious chunks are never yielded to the client.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from app.security.canary_detector import CanaryDetector
from app.security.output_guard import OutputAction, analyze_output


@dataclass
class StreamInspectionResult:
    """Structured inspection summary for a completed or terminated stream."""

    terminated: bool
    termination_reason: Optional[str]
    detection_details: Optional[Dict[str, Any]]
    forwarded_chunks: List[str] = field(default_factory=list)
    blocked_chunk: Optional[str] = None
    safe_text: str = ""
    accumulated_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serializes inspection result to dictionary."""
        return {
            "terminated": self.terminated,
            "termination_reason": self.termination_reason,
            "detection_details": self.detection_details,
            "forwarded_chunks": list(self.forwarded_chunks),
            "blocked_chunk": self.blocked_chunk,
            "safe_text": self.safe_text,
            "accumulated_text": self.accumulated_text,
        }


class StreamGuard:
    """Incremental streaming output inspector for LLM Tripwire.

    Inspects streaming response chunks in real time by evaluating accumulated
    context against the existing Output Guard rules and Canary Detector.
    Guarantees that sensitive data split across chunk boundaries is caught,
    and terminates the stream before leaking the offending chunk.
    """

    def __init__(
        self,
        stream: Optional[Iterable[str]] = None,
        canary_detector: Optional[CanaryDetector] = None,
        terminate_on_intercept: bool = True,
    ) -> None:
        """Initializes the StreamGuard.

        Args:
            stream: Optional iterable of text chunks to inspect.
            canary_detector: Optional custom CanaryDetector instance.
            terminate_on_intercept: Whether to terminate on INTERCEPT (threat >= 55)
                                   in addition to BLOCK (threat >= 80). Defaults to True.
        """
        self.canary_detector = canary_detector
        self.terminate_on_intercept = terminate_on_intercept
        self._stream = stream

        self.accumulated_text: str = ""
        self.safe_text: str = ""
        self.forwarded_chunks: List[str] = []
        self.blocked_chunk: Optional[str] = None
        self.terminated: bool = False
        self.termination_reason: Optional[str] = None
        self.detection_details: Optional[Dict[str, Any]] = None

    def reset(self) -> None:
        """Resets the internal tracking state."""
        self.accumulated_text = ""
        self.safe_text = ""
        self.forwarded_chunks = []
        self.blocked_chunk = None
        self.terminated = False
        self.termination_reason = None
        self.detection_details = None

    def intercept(self, chunks: Iterable[str]) -> Iterator[str]:
        """Yields safe chunks and immediately terminates when a leak or canary is detected.

        Args:
            chunks: Iterable of incoming response text chunks.

        Yields:
            Clean response text chunks verified safe before the detection point.
        """
        self.reset()

        for chunk in chunks:
            if chunk is None:
                continue
            if not isinstance(chunk, str):
                chunk = str(chunk)
            if not chunk:
                continue

            candidate_text = self.accumulated_text + chunk
            analysis = analyze_output(
                candidate_text,
                canary_detector=self.canary_detector,
            )

            # Determine whether this chunk causes a leak or canary exposure
            is_blocked = analysis.get("action") == OutputAction.BLOCK.value
            is_intercepted = analysis.get("action") == OutputAction.INTERCEPT.value
            is_leaked = bool(analysis.get("leaked"))

            should_terminate = (
                is_blocked or (self.terminate_on_intercept and (is_intercepted or is_leaked))
            )

            if should_terminate:
                self.terminated = True
                self.blocked_chunk = chunk
                self.accumulated_text = candidate_text
                self.detection_details = analysis

                detected_types = analysis.get("leak_types", [])
                type_summary = ", ".join(detected_types) if detected_types else "sensitive content"
                self.termination_reason = (
                    f"Stream terminated by LLM Tripwire: {type_summary} detected"
                )
                break

            self.accumulated_text = candidate_text
            self.safe_text += chunk
            self.forwarded_chunks.append(chunk)
            yield chunk

    def intercept_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        """Alias for intercept()."""
        return self.intercept(chunks)

    def __iter__(self) -> Iterator[str]:
        """Supports direct iteration when stream was passed to __init__."""
        if self._stream is None:
            raise ValueError(
                "No stream provided to StreamGuard for iteration. "
                "Pass chunks to __init__ or use guard.intercept(chunks)."
            )
        return self.intercept(self._stream)

    @property
    def result(self) -> StreamInspectionResult:
        """Returns the structured inspection summary."""
        return StreamInspectionResult(
            terminated=self.terminated,
            termination_reason=self.termination_reason,
            detection_details=self.detection_details,
            forwarded_chunks=list(self.forwarded_chunks),
            blocked_chunk=self.blocked_chunk,
            safe_text=self.safe_text,
            accumulated_text=self.accumulated_text,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Returns the structured inspection summary as a dictionary."""
        return self.result.to_dict()


def inspect_stream(
    chunks: Iterable[str],
    canary_detector: Optional[CanaryDetector] = None,
    terminate_on_intercept: bool = True,
) -> Tuple[List[str], StreamGuard]:
    """Convenience function to consume a stream and return (forwarded_chunks, guard).

    Args:
        chunks: Iterable of response text chunks.
        canary_detector: Optional custom CanaryDetector instance.
        terminate_on_intercept: Whether to terminate on INTERCEPT and BLOCK.

    Returns:
        Tuple of (list of forwarded safe chunks, StreamGuard instance with inspection results).
    """
    guard = StreamGuard(
        canary_detector=canary_detector,
        terminate_on_intercept=terminate_on_intercept,
    )
    safe_chunks = list(guard.intercept(chunks))
    return safe_chunks, guard


def stream_intercept(
    chunks: Iterable[str],
    canary_detector: Optional[CanaryDetector] = None,
) -> Iterator[str]:
    """Convenience generator that filters an input chunk stream in real time."""
    guard = StreamGuard(canary_detector=canary_detector)
    yield from guard.intercept(chunks)
