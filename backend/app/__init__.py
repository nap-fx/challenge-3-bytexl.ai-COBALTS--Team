"""
BrandShield AI — Multi-Modal Digital Risk Protection Backend
HacXLerate 2026 | Challenge 03 (Presented by Kampus.vc)
"""

import os
import sys

# Auto-attach local .venv site-packages if launched from global Python
_VENV_SITE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".venv", "Lib", "site-packages")
)
if os.path.isdir(_VENV_SITE) and _VENV_SITE not in sys.path:
    sys.path.insert(0, _VENV_SITE)

__version__ = "1.0.0"
