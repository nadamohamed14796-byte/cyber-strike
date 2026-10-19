#!/usr/bin/env python3
"""Normalize URLs from local files/stdin without making network requests.

Query values and fragments are removed; sorted query-key names are retained as endpoint-shape
hints. Path case is preserved because routes may be case-sensitive.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

def normalize(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("/"):
        parts = urlsplit(raw)
        path = parts.path or "/"
        keys = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})
        return path + (("?" + "&".join(keys)) if keys else "")
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            return None
        host = parts.hostname.lower()
        try:
            port = parts.port
        except ValueError:
            return None
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        keys = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})
        result = urlunsplit((scheme, host, parts.path or "/", "", ""))
        return result + (("?" + "&".join(keys)) if keys else "")
    except ValueError:
        return None

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="file with one URL per line; defaults to stdin")
    args = parser.parse_args()
    try:
        lines = args.file.read_text(encoding="utf-8", errors="replace").splitlines() if args.file else sys.stdin.read().splitlines()
    except OSError as exc:
        print(f"error: unable to read input: {exc}", file=sys.stderr)
        return 2
    values = sorted({candidate for line in lines if (candidate := normalize(line))})
    for value in values:
        print(value)
    print(f"# normalized unique candidates: {len(values)}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
