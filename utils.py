"""utils.py
Auxiliary functions: entropy calculation, normalization, simple checks.
"""
import math
import re

COMMON_PATTERNS = [r"^(?P<num>\d+)$", r"(?i)password", r"(?i)qwerty"]

def estimate_entropy(password: str) -> float:
    """Simple entropy estimation in bits based on character sets used."""
    if not password:
        return 0.0
    sets = 0
    if re.search(r"[a-z]", password):
        sets += 26
    if re.search(r"[A-Z]", password):
        sets += 26
    if re.search(r"[0-9]", password):
        sets += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        sets += 32  # approximation for symbols
    try:
        return len(password) * math.log2(sets) if sets > 0 else 0.0
    except Exception:
        return 0.0

def contains_common_pattern(password: str) -> bool:
    for p in COMMON_PATTERNS:
        if re.search(p, password):
            return True
    return False
