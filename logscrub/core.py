"""Core scrubbing logic."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import patterns


@dataclass
class Result:
    text: str                                    # redacted text
    findings: Counter = field(default_factory=Counter)  # {type: count}

    @property
    def total(self) -> int:
        return sum(self.findings.values())


def _placeholder(kind: str) -> str:
    return f"[REDACTED:{kind}]"


def scrub(text: str, keep: set[str] | None = None) -> Result:
    """Redact secrets and PII from ``text``.

    ``keep`` is a set of detector names to skip (e.g. ``{"email", "ip"}`` to
    leave those in). Returns a :class:`Result` with the redacted text and a
    count of what was removed.
    """
    keep = {k.lower() for k in (keep or set())}
    findings: Counter = Counter()

    def sub_all(detectors, s, value_group=None):
        for name, rx in detectors:
            if name in keep:
                continue

            def repl(m, _name=name):
                if _name == "credit_card" and not patterns.luhn_ok(m.group(0)):
                    return m.group(0)               # not a real card, leave it
                findings[_name] += 1
                if value_group is not None:
                    # keep the "key:" prefix, redact only the value
                    return m.group(1) + m.group(2) + _placeholder(_name)
                return _placeholder(_name)

            s = rx.sub(repl, s)
        return s

    text = sub_all(patterns.NAMED, text)
    text = sub_all(patterns.GENERIC, text, value_group=4)
    text = sub_all(patterns.PII, text)
    return Result(text=text, findings=findings)
