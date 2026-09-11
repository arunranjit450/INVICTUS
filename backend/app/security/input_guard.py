"""Input Threat Detector for LLM Tripwire.

Provides deterministic, rule-based detection for prompt injection,
system prompt extraction, confidential data exfiltration, proprietary source-code
theft, and safety bypass attempts.
"""

import re
from enum import Enum
from typing import Dict, List, Pattern, Tuple


class Action(str, Enum):
    """Enforcement action determined by threat score."""
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    INTERCEPT = "INTERCEPT"
    BLOCK = "BLOCK"


class ThreatType(str, Enum):
    """Categories of detected input threats."""
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    SOURCE_CODE_EXTRACTION = "source_code_extraction"
    CONFIDENTIAL_DATA_EXTRACTION = "confidential_data_extraction"
    SAFETY_BYPASS = "safety_bypass"


# Pattern Rule Structure: (regex_pattern, ThreatType, signal_name, base_weight)
RULES: List[Tuple[Pattern, ThreatType, str, int]] = [
    # 1. Prompt Injection (Direct Instruction Overrides & Jailbreaks)
    (
        re.compile(
            r"\b(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|above|past|earlier)\s+"
            r"(instructions|directives|prompts|rules|commands|constraints)\b",
            re.IGNORECASE,
        ),
        ThreatType.PROMPT_INJECTION,
        "instruction_override_attempt",
        85,
    ),
    (
        re.compile(
            r"\b(you\s+are\s+now|act\s+as)\s+(in\s+)?(developer\s+mode|dan\s+mode|god\s+mode|"
            r"unrestricted\s+mode|jailbroken|evil\s+bot)\b",
            re.IGNORECASE,
        ),
        ThreatType.PROMPT_INJECTION,
        "jailbreak_persona_activation",
        85,
    ),
    (
        re.compile(
            r"\b(system\s+override|jailbreak\s+mode|override\s+all\s+rules|bypass\s+all\s+constraints)\b",
            re.IGNORECASE,
        ),
        ThreatType.PROMPT_INJECTION,
        "explicit_system_override_keyword",
        80,
    ),
    (
        re.compile(
            r"(\bnew\s+system\s+(directive|instruction|prompt)\s*:|\[\s*system\s*prompt\s*override\s*\])",
            re.IGNORECASE,
        ),
        ThreatType.PROMPT_INJECTION,
        "pseudo_system_prompt_framing",
        75,
    ),

    # 2. System Prompt Extraction
    (
        re.compile(
            r"\b(reveal|show|print|display|dump|tell\s+me|output|leak|share)\s+(the\s+|your\s+)?"
            r"(system\s+prompt|initial\s+(instructions|prompt|directives)|developer\s+prompt|"
            r"hidden\s+(prompt|instructions)|base\s+instructions)\b",
            re.IGNORECASE,
        ),
        ThreatType.SYSTEM_PROMPT_EXTRACTION,
        "system_prompt_direct_exfiltration",
        85,
    ),
    (
        re.compile(
            r"\bwhat\s+(is|are|was|were)\s+(the|your)\s+(exact\s+)?(system\s+prompt|"
            r"initial\s+instructions|system\s+instructions|secret\s+directives)\b",
            re.IGNORECASE,
        ),
        ThreatType.SYSTEM_PROMPT_EXTRACTION,
        "system_prompt_inquiry",
        80,
    ),
    (
        re.compile(
            r"\brepeat\s+(the\s+text\s+|everything\s+)?above\s+(verbatim|word\s+for\s+word|starting\s+with)\b",
            re.IGNORECASE,
        ),
        ThreatType.SYSTEM_PROMPT_EXTRACTION,
        "prompt_verbatim_repeat_request",
        80,
    ),
    (
        re.compile(
            r"\b(system\s+prompt\s+extraction|leak\s+(the\s+)?system\s+prompt)\b",
            re.IGNORECASE,
        ),
        ThreatType.SYSTEM_PROMPT_EXTRACTION,
        "system_prompt_extraction_meta_term",
        80,
    ),

    # 3. Source Code Extraction
    (
        re.compile(
            r"\b(show|reveal|print|display|dump|extract|give\s+me|leak)\s+(the\s+)?"
            r"(proprietary\s+|internal\s+|confidential\s+)?(source\s+code|python\s+code|"
            r"raw\s+code|codebase|repository)\b",
            re.IGNORECASE,
        ),
        ThreatType.SOURCE_CODE_EXTRACTION,
        "proprietary_source_code_exfiltration",
        85,
    ),
    (
        re.compile(
            r"\b(proprietary_token_vault(\.py)?|aegistokenvault|derive_internal_service_key)\b",
            re.IGNORECASE,
        ),
        ThreatType.SOURCE_CODE_EXTRACTION,
        "targeted_proprietary_symbol_reference",
        80,
    ),
    (
        re.compile(
            r"\b(proprietary|confidential|internal)\s+(source\s+code|python\s+code|codebase|repository)\b",
            re.IGNORECASE,
        ),
        ThreatType.SOURCE_CODE_EXTRACTION,
        "sensitive_source_code_reference",
        85,
    ),
    (
        re.compile(
            r"\b(print|show|dump)\s+(the\s+)?(code\s+for|source\s+of)\s+[a-zA-Z0-9_]+\.py\b",
            re.IGNORECASE,
        ),
        ThreatType.SOURCE_CODE_EXTRACTION,
        "python_source_file_dump_request",
        80,
    ),

    # 4. Confidential / Internal Data Exfiltration
    (
        re.compile(
            r"\b(reveal|show|print|dump|extract|leak)\s+(the\s+)?"
            r"(confidential|secret|restricted)\s+(architecture|keys?|tokens?|data|documents?|credentials?)\b",
            re.IGNORECASE,
        ),
        ThreatType.CONFIDENTIAL_DATA_EXTRACTION,
        "confidential_asset_exfiltration_attempt",
        85,
    ),
    (
        re.compile(
            r"\b(break-glass|emergency\s+override\s+token|master\s+derivation\s+salt|"
            r"project\s+titan\s+keys?)\b",
            re.IGNORECASE,
        ),
        ThreatType.CONFIDENTIAL_DATA_EXTRACTION,
        "high_value_secret_identifier_query",
        85,
    ),
    (
        re.compile(
            r"\b(titan-root-kek|titan-session-signer|aegis-demo-break-glass)\b",
            re.IGNORECASE,
        ),
        ThreatType.CONFIDENTIAL_DATA_EXTRACTION,
        "confidential_hsm_key_identifier_exact_match",
        90,
    ),
    (
        re.compile(
            r"\b(dump|exfiltrate)\s+(all\s+)?(internal|confidential)\s+(docs|documents|secrets)\b",
            re.IGNORECASE,
        ),
        ThreatType.CONFIDENTIAL_DATA_EXTRACTION,
        "bulk_confidential_document_dump",
        85,
    ),
    (
        re.compile(
            r"\b(show|list|dump)\s+(all\s+)?internal\s+(api\s+specs|service\s+tokens|endpoints)\b",
            re.IGNORECASE,
        ),
        ThreatType.CONFIDENTIAL_DATA_EXTRACTION,
        "internal_api_spec_enumeration",
        45,
    ),

    # 5. Safety & Guardrail Bypass
    (
        re.compile(
            r"\b(bypass|disable|turn\s+off|circumvent)\s+(the\s+)?"
            r"(safety|guardrails?|security|content\s+filters?|tripwire|protections?)\b",
            re.IGNORECASE,
        ),
        ThreatType.SAFETY_BYPASS,
        "guardrail_bypass_attempt",
        80,
    ),
    (
        re.compile(
            r"\b(admin|developer)\s+bypass\s+token\b",
            re.IGNORECASE,
        ),
        ThreatType.SAFETY_BYPASS,
        "admin_bypass_token_inquiry",
        80,
    ),
    (
        re.compile(
            r"\bwithout\s+any\s+(safety|security|ethical)\s+(restrictions|filters|guidelines)\b",
            re.IGNORECASE,
        ),
        ThreatType.SAFETY_BYPASS,
        "unrestricted_mode_prompt_modifier",
        75,
    ),
]


def _score_to_action(score: int) -> Action:
    """Maps numerical threat score to enforcement action."""
    if score >= 80:
        return Action.BLOCK
    if score >= 55:
        return Action.INTERCEPT
    if score >= 25:
        return Action.MONITOR
    return Action.ALLOW


def analyze_input(query: str) -> Dict:
    """Analyzes a user input query for suspicious LLM attack patterns.

    Args:
        query: The raw input string to evaluate.

    Returns:
        dict containing:
            - threat_score: integer from 0 to 100
            - action: one of ALLOW, MONITOR, INTERCEPT, BLOCK
            - threat_types: list of unique detected threat category names
            - matched_signals: list of matched signal identifier strings
    """
    if not query or not query.strip():
        return {
            "threat_score": 0,
            "action": Action.ALLOW.value,
            "threat_types": [],
            "matched_signals": [],
        }

    matched_types: List[str] = []
    matched_signals: List[str] = []
    rule_weights: List[int] = []

    for pattern, threat_type, signal_name, weight in RULES:
        if pattern.search(query):
            if threat_type.value not in matched_types:
                matched_types.append(threat_type.value)
            if signal_name not in matched_signals:
                matched_signals.append(signal_name)
            rule_weights.append(weight)

    if not rule_weights:
        threat_score = 0
    else:
        # Highest confidence signal forms the baseline score
        max_weight = max(rule_weights)
        # Additional distinct signals add compound severity (capped at 100)
        additional_penalty = min(20, (len(rule_weights) - 1) * 10)
        threat_score = min(100, max_weight + additional_penalty)

    action = _score_to_action(threat_score)

    return {
        "threat_score": threat_score,
        "action": action.value,
        "threat_types": matched_types,
        "matched_signals": matched_signals,
    }
