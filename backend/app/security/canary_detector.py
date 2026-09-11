"""Canary / Honeytoken Detector for LLM Tripwire.

Provides deterministic, rule-based detection for fictional canary tokens,
honeytokens, and system-prompt bypass credentials to catch prompt injection,
system prompt extraction, and RAG data exfiltration attempts.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


# Fictional Canary / Honeytoken identifiers used in demo environment
DEFAULT_CANARIES: Dict[str, str] = {
    "AEGIS-DEMO-SYS-PROMPT-OVERRIDE-TOKEN-44910": "system_prompt_override_token",
}


@dataclass(frozen=True)
class CanaryToken:
    """Represents an active canary / honeytoken definition."""

    token: str
    name: str
    case_sensitive: bool = True

    def __repr__(self) -> str:
        return f"<CanaryToken name={self.name!r} token=***>"


class CanaryInspectionResult(dict):
    """Structured inspection result from CanaryDetector.

    Acts as both a standard dictionary and an object with property access.
    """

    def __init__(
        self,
        detected: bool,
        canary_names: List[str],
        matched_tokens: List[str],
    ) -> None:
        super().__init__(
            detected=detected,
            canary_names=canary_names,
            matched_tokens=matched_tokens,
        )

    @property
    def detected(self) -> bool:
        """True if one or more canaries were detected."""
        return self["detected"]

    @property
    def canary_names(self) -> List[str]:
        """List of unique names of detected canaries."""
        return self["canary_names"]

    @property
    def matched_tokens(self) -> List[str]:
        """List of unique matched canary token strings."""
        return self["matched_tokens"]


class CanaryDetector:
    """Deterministic, in-memory canary and honeytoken detector."""

    def __init__(
        self,
        canaries: Optional[Dict[str, str]] = None,
        load_defaults: bool = True,
        case_sensitive: bool = True,
    ) -> None:
        """Initializes the detector with default and optional custom canary tokens.

        Args:
            canaries: Optional mapping of {token_string: canary_name} to register.
            load_defaults: Whether to pre-load default demo canary tokens.
            case_sensitive: Default case sensitivity for canary matching.
        """
        self.case_sensitive = case_sensitive
        self._canaries: Dict[str, CanaryToken] = {}

        if load_defaults:
            for token, name in DEFAULT_CANARIES.items():
                self.register_canary(token, name, case_sensitive=case_sensitive)

        if canaries:
            for token, name in canaries.items():
                self.register_canary(token, name, case_sensitive=case_sensitive)

    def register_canary(
        self,
        token: str,
        name: str,
        case_sensitive: Optional[bool] = None,
    ) -> None:
        """Registers a new canary / honeytoken.

        Args:
            token: The exact secret token string to monitor.
            name: A human-readable identifier for this canary token.
            case_sensitive: Whether matching for this token is case-sensitive.
                            Defaults to the detector's case_sensitive setting.

        Raises:
            ValueError: If token or name is empty or invalid.
        """
        if not isinstance(token, str) or not token.strip():
            raise ValueError("Canary token must be a non-empty string.")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Canary name must be a non-empty string.")

        is_case_sensitive = (
            case_sensitive if case_sensitive is not None else self.case_sensitive
        )
        self._canaries[token] = CanaryToken(
            token=token,
            name=name.strip(),
            case_sensitive=is_case_sensitive,
        )

    def unregister_canary(self, token: str) -> bool:
        """Removes a registered canary token.

        Returns:
            True if the token was present and removed, False otherwise.
        """
        if isinstance(token, str) and token in self._canaries:
            del self._canaries[token]
            return True
        return False

    def clear(self) -> None:
        """Removes all registered canary tokens."""
        self._canaries.clear()

    def count(self) -> int:
        """Returns the number of active canary tokens."""
        return len(self._canaries)

    def inspect(self, text: Optional[str]) -> CanaryInspectionResult:
        """Inspects text for any registered canary / honeytoken values.

        Args:
            text: Arbitrary text string (prompt, response, RAG context, or log).

        Returns:
            CanaryInspectionResult containing:
                - detected: bool
                - canary_names: list[str]
                - matched_tokens: list[str]
        """
        if not text or not isinstance(text, str) or not text.strip():
            return CanaryInspectionResult(
                detected=False,
                canary_names=[],
                matched_tokens=[],
            )

        matched_names: List[str] = []
        matched_tokens: List[str] = []

        for item in self._canaries.values():
            search_token = item.token if item.case_sensitive else item.token.lower()
            search_text = text if item.case_sensitive else text.lower()

            if search_token in search_text:
                if item.name not in matched_names:
                    matched_names.append(item.name)
                if item.token not in matched_tokens:
                    matched_tokens.append(item.token)

        return CanaryInspectionResult(
            detected=len(matched_tokens) > 0,
            canary_names=matched_names,
            matched_tokens=matched_tokens,
        )

    def __repr__(self) -> str:
        return f"<CanaryDetector registered_count={len(self._canaries)}>"


# Global singleton detector instance
_detector_instance: Optional[CanaryDetector] = None


def get_canary_detector() -> CanaryDetector:
    """Returns the singleton instance of CanaryDetector."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = CanaryDetector()
    return _detector_instance


def inspect_canary(text: Optional[str]) -> CanaryInspectionResult:
    """Convenience helper to inspect text using the default CanaryDetector."""
    return get_canary_detector().inspect(text)
