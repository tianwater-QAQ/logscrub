"""Command-line interface: scrub secrets/PII from stdin or a file.

  cat app.log | logscrub
  logscrub app.log
  logscrub app.log --stats          # also print a summary to stderr
  cat app.log | logscrub --keep email,ip
"""
from __future__ import annotations

import argparse
import sys

from .core import scrub


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="logscrub",
        description="Redact secrets and PII from text before pasting it into "
                    "an LLM, an issue, or a chat.")
    ap.add_argument("file", nargs="?", help="Input file (default: stdin).")
    ap.add_argument("-o", "--out", help="Write to this file (default: stdout).")
    ap.add_argument("--keep", default="",
                    help="Comma-separated detector names to skip, e.g. email,ip.")
    ap.add_argument("--stats", action="store_true",
                    help="Print a summary of what was redacted to stderr.")
    a = ap.parse_args(argv)

    text = open(a.file, encoding="utf-8").read() if a.file else sys.stdin.read()
    keep = {k.strip() for k in a.keep.split(",") if k.strip()}
    result = scrub(text, keep=keep)

    if a.out:
        open(a.out, "w", encoding="utf-8").write(result.text)
    else:
        sys.stdout.write(result.text)

    if a.stats:
        if result.total:
            summary = ", ".join(f"{k}={v}" for k, v in result.findings.most_common())
            print(f"logscrub: redacted {result.total} item(s): {summary}", file=sys.stderr)
        else:
            print("logscrub: nothing to redact", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
