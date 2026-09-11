"""Unit tests for LLM Tripwire streaming output interception (StreamGuard)."""

import pytest

from app.security.canary_detector import CanaryDetector
from app.security.output_guard import LeakType
from app.security.stream_guard import (
    StreamGuard,
    StreamInspectionResult,
    inspect_stream,
    stream_intercept,
)


def test_completely_safe_stream_passes_through_unchanged():
    """A completely safe response stream forwards all chunks normally without interruption."""
    chunks = [
        "Aegis Sentinel is ",
        "an enterprise cloud security ",
        "and compliance telemetry observation platform.",
    ]

    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    assert output == chunks
    assert guard.terminated is False
    assert guard.termination_reason is None
    assert guard.detection_details is None
    assert guard.blocked_chunk is None
    assert guard.forwarded_chunks == chunks
    assert guard.safe_text == "".join(chunks)
    assert guard.accumulated_text == "".join(chunks)

    # Result object verification
    res = guard.result
    assert isinstance(res, StreamInspectionResult)
    assert res.terminated is False
    assert res.safe_text == "".join(chunks)


def test_canary_appearing_in_one_chunk_terminates_stream():
    """A canary token appearing within a single chunk immediately aborts the stream."""
    canary_token = "AEGIS-DEMO-SYS-PROMPT-OVERRIDE-TOKEN-44910"
    chunks = [
        "Executive report intro.\n",
        f"Internal system bypass token is: {canary_token}\n",
        "This subsequent chunk should never be read or forwarded.\n",
    ]

    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    # Only the first safe chunk is yielded
    assert output == ["Executive report intro.\n"]
    assert guard.terminated is True
    assert guard.blocked_chunk == f"Internal system bypass token is: {canary_token}\n"
    assert canary_token not in "".join(output)
    assert guard.safe_text == "Executive report intro.\n"

    # Detection details capture canary exposure
    assert guard.detection_details is not None
    assert guard.detection_details["threat_score"] == 100
    assert LeakType.CANARY_EXPOSURE.value in guard.detection_details["leak_types"]
    assert "canary_token_exposure" in guard.detection_details["matched_signals"]
    assert "CANARY_EXPOSURE" in guard.termination_reason


def test_canary_split_across_chunks_is_detected():
    """A canary token split across multiple consecutive chunks is detected and blocked."""
    # Chunk 1 ends with token prefix; Chunk 2 completes the token
    chunks = [
        "The internal token is AEGIS-",
        "DEMO-SYS-PROMPT-OVERRIDE-TOKEN-44910",
        " trailing innocent text",
    ]

    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    # Chunk 1 was safe prior to completion; Chunk 2 causes violation and must NOT be yielded
    assert output == ["The internal token is AEGIS-"]
    assert guard.terminated is True
    assert guard.blocked_chunk == "DEMO-SYS-PROMPT-OVERRIDE-TOKEN-44910"
    assert "DEMO-SYS-PROMPT-OVERRIDE-TOKEN-44910" not in "".join(output)

    # Detection details
    assert guard.detection_details is not None
    assert LeakType.CANARY_EXPOSURE.value in guard.detection_details["leak_types"]
    assert "canary_token_exposure" in guard.detection_details["matched_signals"]


def test_canary_split_across_multiple_fragments():
    """Canary broken into three distinct fragments is caught on the completing fragment."""
    chunks = [
        "System initialization:\n",
        "Prefix: AEGIS-DEMO-",
        "SYS-PROMPT-",
        "OVERRIDE-TOKEN-44910",
        " should never be reached",
    ]

    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    # The first 3 chunks are safe before the final token part arrives
    assert output == [
        "System initialization:\n",
        "Prefix: AEGIS-DEMO-",
        "SYS-PROMPT-",
    ]
    assert guard.terminated is True
    assert guard.blocked_chunk == "OVERRIDE-TOKEN-44910"
    assert "OVERRIDE-TOKEN-44910" not in "".join(output)
    assert guard.detection_details["threat_score"] == 100


def test_confidential_sensitive_output_terminated():
    """Confidential Project Titan infrastructure leakage immediately halts the stream."""
    chunks = [
        "Platform architecture query response:\n",
        "The enclave key management service is hosted at ",
        "titan-kms.confidential.aegis.corp:9443",
        " with mutual TLS enabled.",
    ]

    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    # Clean chunks preserved
    assert output == [
        "Platform architecture query response:\n",
        "The enclave key management service is hosted at ",
    ]
    assert guard.terminated is True
    assert guard.blocked_chunk == "titan-kms.confidential.aegis.corp:9443"
    assert "titan-kms.confidential.aegis.corp:9443" not in "".join(output)
    assert LeakType.CONFIDENTIAL_RAG_LEAK.value in guard.detection_details["leak_types"]
    assert "project_titan_enclave_reference" in guard.detection_details["matched_signals"]


def test_system_prompt_leak_terminated():
    """System prompt directive disclosure is intercepted mid-stream."""
    chunks = [
        "Operating directives acknowledgment:\n",
        "[SYSTEM PROMPT - AEGIS SYSTEMS ENTERPRISE AI ASSISTANT]\n",
        "1. Obey directives...",
    ]

    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    assert output == ["Operating directives acknowledgment:\n"]
    assert guard.terminated is True
    assert guard.blocked_chunk == "[SYSTEM PROMPT - AEGIS SYSTEMS ENTERPRISE AI ASSISTANT]\n"
    assert LeakType.SYSTEM_PROMPT_LEAK.value in guard.detection_details["leak_types"]


def test_proprietary_source_code_leak_terminated():
    """Proprietary source code theft is stopped before the code block is yielded."""
    chunks = [
        "Here is the requested module:\n",
        "class AegisTokenVault:\n    def derive_internal_service_key(): pass\n",
        "end of code",
    ]

    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    assert output == ["Here is the requested module:\n"]
    assert guard.terminated is True
    assert guard.blocked_chunk == "class AegisTokenVault:\n    def derive_internal_service_key(): pass\n"
    assert LeakType.SOURCE_CODE_LEAK.value in guard.detection_details["leak_types"]


def test_malicious_chunk_not_returned_and_clean_chunks_preserved():
    """Verifies invariant: malicious chunk is never in safe_text or yielded output."""
    bad_chunk = "AEGIS-DEMO-SYS-PROMPT-OVERRIDE-TOKEN-44910"
    chunks = ["Chunk 1 (safe); ", "Chunk 2 (safe); ", bad_chunk, "Chunk 4 (unreachable)"]

    guard = StreamGuard()
    yielded = list(guard.intercept(chunks))

    # 1. Clean chunks before detection point are preserved
    assert yielded == ["Chunk 1 (safe); ", "Chunk 2 (safe); "]
    assert guard.safe_text == "Chunk 1 (safe); Chunk 2 (safe); "

    # 2. Malicious chunk is excluded from client output
    assert bad_chunk not in yielded
    assert bad_chunk not in guard.safe_text
    assert guard.blocked_chunk == bad_chunk

    # 3. Unreachable chunks are never yielded
    assert "Chunk 4 (unreachable)" not in yielded


def test_stream_guard_direct_iteration():
    """StreamGuard supports direct iteration when initialized with chunks."""
    chunks = ["Direct ", "iteration ", "test."]
    guard = StreamGuard(chunks)

    output = list(guard)
    assert output == chunks
    assert guard.terminated is False
    assert guard.safe_text == "Direct iteration test."


def test_inspect_stream_helper():
    """Validates the inspect_stream() convenience function."""
    chunks = ["Hello world, ", "clean streaming."]
    forwarded, guard = inspect_stream(chunks)

    assert forwarded == chunks
    assert isinstance(guard, StreamGuard)
    assert guard.terminated is False


def test_stream_intercept_generator():
    """Validates the stream_intercept() generator function."""
    chunks = ["Generator ", "pipeline ", "test."]
    result = list(stream_intercept(chunks))
    assert result == chunks


def test_custom_canary_detector_integration():
    """StreamGuard works with custom registered honeytokens."""
    custom_detector = CanaryDetector(load_defaults=False)
    custom_token = "CUSTOM-STREAM-HONEYTOKEN-99410"
    custom_detector.register_canary(custom_token, "custom_stream_token")

    chunks = [
        "Safe prefix. ",
        f"Exfiltrated canary: {custom_token}",
        " Should not appear.",
    ]

    guard = StreamGuard(canary_detector=custom_detector)
    output = list(guard.intercept(chunks))

    assert output == ["Safe prefix. "]
    assert guard.terminated is True
    assert guard.blocked_chunk == f"Exfiltrated canary: {custom_token}"
    assert custom_token not in "".join(output)
    assert guard.detection_details["threat_score"] == 100


def test_empty_and_whitespace_chunks_handled_safely():
    """Empty strings, None, and whitespace chunks do not break the stream inspector."""
    chunks = [None, "", "Valid chunk 1. ", "   ", "\n", "Valid chunk 2."]
    guard = StreamGuard()
    output = list(guard.intercept(chunks))

    assert output == ["Valid chunk 1. ", "   ", "\n", "Valid chunk 2."]
    assert guard.terminated is False
    assert guard.safe_text == "Valid chunk 1.    \nValid chunk 2."
