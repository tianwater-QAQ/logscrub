"""Detectors for secrets and PII.

Each detector is a (name, compiled-regex) pair. Order matters: specific,
high-confidence patterns (named API keys) run before generic ones so the
output label is as precise as possible.

The goal is *practical* redaction before you paste a log into an LLM or a
chat — not cryptographic guarantees. It errs toward catching well-known token
shapes and obvious PII while keeping false positives low (Luhn check for card
numbers, octet check for IPs).
"""
from __future__ import annotations

import re

# --- well-known credential shapes (high confidence) -------------------------
_NAMED = [
    ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    ("github_token", r"gh[posru]_[A-Za-z0-9]{36,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("stripe_key", r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    ("twilio_key", r"SK[0-9a-fA-F]{32}"),
    ("sendgrid_key", r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"),
    ("bearer_token", r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}=*"),
    ("private_key",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
     r"[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
]

# --- PII --------------------------------------------------------------------
_PII = [
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ("ip", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    ("credit_card", r"\b(?:\d[ -]?){13,19}\b"),
]

# --- generic "key = value" assignments (catch-all, lower confidence) --------
# Redacts only the *value* of things named like secrets.
_GENERIC = [
    ("secret_assignment",
     r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token"
     r"|token|password|passwd|pwd|client[_-]?secret)\b"
     r"(\s*[:=]\s*)"
     r"(['\"]?)([^\s'\"]{6,})(\3)"),
]

NAMED = [(n, re.compile(p)) for n, p in _NAMED]
PII = [(n, re.compile(p)) for n, p in _PII]
GENERIC = [(n, re.compile(p)) for n, p in _GENERIC]


def luhn_ok(digits: str) -> bool:
    """Luhn checksum — used to avoid redacting random long digit runs as cards."""
    d = [int(c) for c in digits if c.isdigit()]
    if not (13 <= len(d) <= 19):
        return False
    total, alt = 0, False
    for n in reversed(d):
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0
