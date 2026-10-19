#!/usr/bin/env python3
"""Extract conservative endpoint candidates from JavaScript assets collected locally.

This script does not fetch URLs, execute JavaScript, or validate endpoint liveness.
It prints file and line metadata with query values stripped.
"""
from __future__ import annotations
import argparse
import re
from pathlib import Path
from urllib.parse import urlsplit

EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".json", ".map"}
URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
PATH_RE = re.compile(r"""(?<![A-Za-z0-9])/(?:api|graphql|rest|v[0-9]+|oauth|auth|admin|internal)/[A-Za-z0-9_./{}:-]{1,180}""", re.I)
SENSITIVE = re.compile(r"(?i)(token|secret|password|api[_-]?key|authorization|cookie|signature|session)")

def safe_candidate(value: str) -> str | None:
    value = value.strip().strip("\"' ),;")
    if SENSITIVE.search(value):
        return None
    if value.startswith("/"):
        return value.split("?", 1)[0]
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    return f"{parts.scheme.lower()}://{parts.hostname.lower()}{parts.path or '/'}"

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path("./javascript"))
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error(f"asset directory does not exist: {args.root}")
    seen: set[tuple[str, int, str]] = set()
    for file in sorted(args.root.rglob("*")):
        if not file.is_file() or file.suffix.lower() not in EXTS:
            continue
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for raw in (*URL_RE.findall(line), *PATH_RE.findall(line)):
                candidate = safe_candidate(raw)
                if not candidate:
                    continue
                key = (str(file), line_number, candidate)
                if key not in seen:
                    seen.add(key)
                    print(f"{file}:{line_number}\t{candidate}")
    print(f"# unique file/location/candidate records: {len(seen)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
