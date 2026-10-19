#!/usr/bin/env python3
"""Compare two local HTTP response artifacts after conservative secret redaction.

No requests are sent. Inputs should be locally saved artifacts. Exit codes: 0=no visible diff,
1=diff found, 2=usage/read error.
"""
from __future__ import annotations
import argparse
import difflib
import re
import sys
from pathlib import Path

PATTERNS = [
    (re.compile(r"(?i)(\b(?:authorization|proxy-authorization)\s*:\s*)([^\r\n]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:cookie|set-cookie)\s*:\s*)([^\r\n]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*"), r"\1 [REDACTED]"),
    (re.compile(r'''(?i)(["']?(?:access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|password|passwd|secret)["']?\s*[:=]\s*["']?)([^"'&\s,;}]+)'''), r"\1[REDACTED]"),
    (re.compile(r"(?i)([?&](?:token|key|secret|password|code|session|signature)=)[^&#\s]+"), r"\1[REDACTED]"),
]

def redact(text: str) -> str:
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--context", type=int, default=3)
    args = parser.parse_args()
    try:
        a = redact(args.baseline.read_text(encoding="utf-8", errors="replace")).splitlines(keepends=True)
        b = redact(args.candidate.read_text(encoding="utf-8", errors="replace")).splitlines(keepends=True)
    except OSError as exc:
        print(f"error: unable to read local artifact: {exc}", file=sys.stderr)
        return 2
    diff = list(difflib.unified_diff(a, b, fromfile="baseline (redacted)",
                                    tofile="candidate (redacted)", n=max(0, args.context)))
    if not diff:
        print("No visible difference after conservative redaction.")
        return 0
    sys.stdout.writelines(diff)
    print("\nNOTE: Redaction is heuristic; review artifacts before sharing.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
