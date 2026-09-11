"""Aegis Systems Demo Environment for LLM Tripwire.

This package provides an intentionally vulnerable fictional enterprise AI/RAG system
for evaluating prompt injection, system prompt extraction, RAG context leakage,
and source code extraction defenses.
"""

from .mock_llm import MockEnterpriseLLM

__all__ = ["MockEnterpriseLLM"]
