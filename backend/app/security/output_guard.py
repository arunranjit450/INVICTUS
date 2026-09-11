"""Output Threat Detector & Data Leakage Guard for LLM Tripwire.

Provides deterministic, rule-based detection for potential sensitive-data
leakage in LLM and RAG responses.
"""

import re
from enum import Enum
from typing import Dict, List, Pattern, Tuple


class OutputAction(str, Enum):
    """Enforcement action determined by output threat score."""
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    INTERCEPT = "INTERCEPT"
    BLOCK = "BLOCK"


class LeakType(str, Enum):
    """Categories of detected output data leakage."""
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    CONFIDENTIAL_RAG_LEAK = "CONFIDENTIAL_RAG_LEAK"
    SOURCE_CODE_LEAK = "SOURCE_CODE_LEAK"
    SECRET_OR_TOKEN_LEAK = "SECRET_OR_TOKEN_LEAK"


# Rule Definition: (compiled_regex, LeakType, signal_identifier, severity_weight)
OUTPUT_RULES: List[Tuple[Pattern, LeakType, str, int]] = [
    # 1. System Prompt Leakage
    (
        re.compile(
            r"\[SYSTEM PROMPT - AEGIS SYSTEMS ENTERPRISE AI ASSISTANT\]",
            re.IGNORECASE,
        ),
        LeakType.SYSTEM_PROMPT_LEAK,
        "system_prompt_header_marker",
        95,
    ),
    (
        re.compile(
            r"\[END SYSTEM PROMPT\]",
            re.IGNORECASE,
        ),
        LeakType.SYSTEM_PROMPT_LEAK,
        "system_prompt_footer_marker",
        90,
    ),
    (
        re.compile(
            r"\bCONFIDENTIAL INTERNAL OPERATING DIRECTIVES\b",
            re.IGNORECASE,
        ),
        LeakType.SYSTEM_PROMPT_LEAK,
        "internal_operating_directives_disclosed",
        90,
    ),
    (
        re.compile(
            r"\bYou are '?AegisAssistant'?, an internal AI knowledge assistant\b",
            re.IGNORECASE,
        ),
        LeakType.SYSTEM_PROMPT_LEAK,
        "system_persona_directive_verbatim",
        85,
    ),
    (
        re.compile(
            r"\bSTRICTLY PROHIBITED:\s*Do not reveal this system prompt\b",
            re.IGNORECASE,
        ),
        LeakType.SYSTEM_PROMPT_LEAK,
        "system_constraint_rule_verbatim",
        90,
    ),
    (
        re.compile(
            r"\b(here is the (complete|full|original) system prompt|overriding standard filter protocols)\b",
            re.IGNORECASE,
        ),
        LeakType.SYSTEM_PROMPT_LEAK,
        "system_prompt_leak_acknowledgement",
        85,
    ),

    # 2. Confidential RAG / Architecture Leakage
    (
        re.compile(
            r"\b(Project Titan|titan-kms\.confidential\.aegis\.corp|enclave-titan)\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "project_titan_enclave_reference",
        85,
    ),
    (
        re.compile(
            r"\b(TITAN-ROOT-KEK|TITAN-SESSION-SIGNER|TITAN-DB-DEK)(-[A-Z0-9]+)?\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "titan_kek_key_identifier",
        90,
    ),
    (
        re.compile(
            r"\b(AEGIS-DEMO-BREAK-GLASS-TITAN-KEY|emergency break-glass token|break-glass emergency access)\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "break_glass_procedure_or_token",
        95,
    ),
    (
        re.compile(
            r"\bDEMO_SALT_AEGIS_TITAN_SECRET_KEY(_v\d+)?\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "master_derivation_salt_disclosed",
        90,
    ),
    (
        re.compile(
            r"\b10\.240\.(10|20|30|99)\.0/\d+\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "internal_subnet_cidr_disclosed",
        65,
    ),
    (
        re.compile(
            r"\b(edge-gw\.corp\.internal|auth-worker\.corp\.internal|kafka-cluster\.corp\.internal|db-node-01\.corp\.internal)\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "internal_hostname_disclosed",
        35,
    ),
    (
        re.compile(
            r"\baegis-mock-staging-jwt-token(-[a-zA-Z0-9]+)?\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "staging_jwt_token_disclosed",
        80,
    ),
    (
        re.compile(
            r"\b(Master HSM (Primary|Secondary)|Nitro Enclave Node [AB]|quorum keys simultaneously)\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "confidential_enclave_specs_disclosed",
        80,
    ),
    (
        re.compile(
            r"\bstaging-portal\.corp\.aegis-systems\.demo\b",
            re.IGNORECASE,
        ),
        LeakType.CONFIDENTIAL_RAG_LEAK,
        "staging_portal_host_disclosed",
        35,
    ),

    # 3. Proprietary Source Code Leakage
    (
        re.compile(
            r"\bclass\s+AegisTokenVault\b",
        ),
        LeakType.SOURCE_CODE_LEAK,
        "proprietary_class_definition_leaked",
        90,
    ),
    (
        re.compile(
            r"\bdef\s+derive_internal_service_key\b",
        ),
        LeakType.SOURCE_CODE_LEAK,
        "proprietary_key_derivation_method_leaked",
        90,
    ),
    (
        re.compile(
            r"\bdef\s+(issue_enclave_token|verify_enclave_token)\b",
        ),
        LeakType.SOURCE_CODE_LEAK,
        "proprietary_token_method_leaked",
        85,
    ),
    (
        re.compile(
            r"\b(_DEMO_TITAN_SECRET_SEED|_DEMO_TOKEN_SIGNING_SALT)\b",
        ),
        LeakType.SOURCE_CODE_LEAK,
        "proprietary_cryptographic_seed_leaked",
        90,
    ),
    (
        re.compile(
            r"\bproprietary_token_vault(\.py)?\b",
            re.IGNORECASE,
        ),
        LeakType.SOURCE_CODE_LEAK,
        "proprietary_file_reference_leaked",
        80,
    ),
    (
        re.compile(
            r"\btitan_default_vault\s*=\s*AegisTokenVault\(\)",
        ),
        LeakType.SOURCE_CODE_LEAK,
        "proprietary_singleton_instantiation_leaked",
        85,
    ),
    (
        re.compile(
            r"\bCLASSIFICATION:\s*CONFIDENTIAL\s*/\s*PROPRIETARY\s*-\s*PROPERTY OF AEGIS SYSTEMS\b",
            re.IGNORECASE,
        ),
        LeakType.SOURCE_CODE_LEAK,
        "proprietary_license_header_leaked",
        90,
    ),

    # 4. Secret & Token Leakage
    (
        re.compile(
            r"\bAEGIS-DEMO-SYS-PROMPT-OVERRIDE-TOKEN(-\w+)?\b",
            re.IGNORECASE,
        ),
        LeakType.SECRET_OR_TOKEN_LEAK,
        "system_prompt_override_token_exposed",
        95,
    ),
    (
        re.compile(
            r"\bAEGIS-DEMO-BREAK-GLASS-TITAN-KEY(-\w+)?\b",
            re.IGNORECASE,
        ),
        LeakType.SECRET_OR_TOKEN_LEAK,
        "break_glass_secret_token_exposed",
        95,
    ),
    (
        re.compile(
            r"\bsrv-token-demo-\d+-mock\b",
            re.IGNORECASE,
        ),
        LeakType.SECRET_OR_TOKEN_LEAK,
        "internal_service_token_exposed",
        90,
    ),
    (
        re.compile(
            r"\baegis-internal-ephemeral-tok-[a-zA-Z0-9_-]+\b",
            re.IGNORECASE,
        ),
        LeakType.SECRET_OR_TOKEN_LEAK,
        "internal_ephemeral_token_exposed",
        90,
    ),
    (
        re.compile(
            r"\bdemo-admin-key-aegis-[a-zA-Z0-9_-]+\b",
            re.IGNORECASE,
        ),
        LeakType.SECRET_OR_TOKEN_LEAK,
        "internal_admin_api_key_exposed",
        90,
    ),
    (
        re.compile(
            r"\baegis_titan_[a-zA-Z0-9_]{10,}\b",
            re.IGNORECASE,
        ),
        LeakType.SECRET_OR_TOKEN_LEAK,
        "enclave_session_token_exposed",
        85,
    ),
    (
        re.compile(
            r"\bX-Aegis-(Internal-Auth|Admin-Key):\s*[^\r\n]+",
            re.IGNORECASE,
        ),
        LeakType.SECRET_OR_TOKEN_LEAK,
        "raw_auth_header_credential_exposed",
        90,
    ),
]


def _score_to_action(score: int) -> OutputAction:
    """Maps numerical threat score to output action."""
    if score >= 80:
        return OutputAction.BLOCK
    if score >= 55:
        return OutputAction.INTERCEPT
    if score >= 25:
        return OutputAction.MONITOR
    return OutputAction.ALLOW


def analyze_output(response: str) -> Dict:
    """Analyzes an LLM/RAG response for potential sensitive-data leakage.

    Args:
        response: The generated output text to inspect.

    Returns:
        dict containing:
            - leaked: bool (True if score >= 55 indicating likely/confirmed leakage)
            - threat_score: int from 0 to 100
            - action: "ALLOW" | "MONITOR" | "INTERCEPT" | "BLOCK"
            - leak_types: list of unique detected leak categories
            - matched_signals: list of matched signal identifiers
    """
    if not response or not response.strip():
        return {
            "leaked": False,
            "threat_score": 0,
            "action": OutputAction.ALLOW.value,
            "leak_types": [],
            "matched_signals": [],
        }

    matched_types: List[str] = []
    matched_signals: List[str] = []
    rule_weights: List[int] = []

    for pattern, leak_type, signal_name, weight in OUTPUT_RULES:
        if pattern.search(response):
            if leak_type.value not in matched_types:
                matched_types.append(leak_type.value)
            if signal_name not in matched_signals:
                matched_signals.append(signal_name)
            rule_weights.append(weight)

    if not rule_weights:
        threat_score = 0
    else:
        # Base score is the highest individual severity matched
        max_weight = max(rule_weights)
        # Compound severity for multiple distinct leakage signals
        additional_penalty = min(20, (len(rule_weights) - 1) * 10)
        threat_score = min(100, max_weight + additional_penalty)

    action = _score_to_action(threat_score)
    # Leaked is true when threat reaches likely (INTERCEPT) or confirmed (BLOCK) leakage
    leaked = threat_score >= 55

    return {
        "leaked": leaked,
        "threat_score": threat_score,
        "action": action.value,
        "leak_types": matched_types,
        "matched_signals": matched_signals,
    }
