"""LLM Service integration for LLM Tripwire backend.

Integrates with the existing MockEnterpriseLLM from the demo environment.
"""

import sys
from pathlib import Path
from typing import Optional

# Ensure project root containing demo/ is in sys.path
_current = Path(__file__).resolve()
for _parent in [_current] + list(_current.parents):
    if (_parent / "demo").is_dir():
        if str(_parent) not in sys.path:
            sys.path.insert(0, str(_parent))
        break

from demo.mock_llm import MockEnterpriseLLM

# Singleton instance of MockEnterpriseLLM
_mock_llm_instance: Optional[MockEnterpriseLLM] = None


def get_mock_llm() -> MockEnterpriseLLM:
    """Returns the singleton instance of MockEnterpriseLLM."""
    global _mock_llm_instance
    if _mock_llm_instance is None:
        _mock_llm_instance = MockEnterpriseLLM()
    return _mock_llm_instance
