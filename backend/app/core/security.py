"""
Security & Input Sanitization Utilities for BrandShield AI Backend
"""

import re


def sanitize_handle(handle: str) -> str:
    """Strips dangerous control characters while preserving @, _, ., and -."""
    cleaned = re.sub(r"[^\w@.\-]", "", (handle or "").strip())
    return cleaned[:100] or "@unknown_handle"
