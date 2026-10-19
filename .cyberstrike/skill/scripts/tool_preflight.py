#!/usr/bin/env python3
"""Check whether selected CLI tools are available and record their version output.

Examples:
  python3 .cyberstrike/skill/scripts/tool_preflight.py subfinder dnsx httpx
  python3 .cyberstrike/skill/scripts/tool_preflight.py --json nuclei jq rg
  python3 .cyberstrike/skill/scripts/tool_preflight.py --version-arg -V nmap

This performs local version checks only. It does not install tools or contact targets.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any


def check(command: str, version_arg: str, timeout: float) -> dict[str, Any]:
    path = shutil.which(command)
    record: dict[str, Any] = {
        "tool": command,
        "available": bool(path),
        "path": path,
        "version_arg": version_arg,
        "version": None,
        "version_check_ok": False,
        "error": None,
    }
    if not path:
        record["error"] = "not_found_on_PATH"
        return record
    try:
        proc = subprocess.run(
            [path, version_arg],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (proc.stdout + "\n" + proc.stderr).strip()
        record["version"] = output[:1200] if output else None
        record["exit_code"] = proc.returncode
        record["version_check_ok"] = proc.returncode == 0 and bool(output)
        if proc.returncode != 0:
            record["error"] = "version_command_nonzero"
        elif not output:
            record["error"] = "version_command_empty_output"
    except subprocess.TimeoutExpired:
        record["error"] = "version_command_timeout"
    except OSError as exc:
        record["error"] = f"execution_error:{type(exc).__name__}"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", nargs="+", help="CLI executable names to check")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--version-arg", default="--version", help="version flag (default: --version)")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-tool timeout in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    # Preserve first-seen order while avoiding duplicate checks.
    names = list(dict.fromkeys(args.tools))
    checks = [check(name, args.version_arg, args.timeout) for name in names]
    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "check_type": "local_cli_presence_and_version",
        "does_not_install_tools": True,
        "summary": {
            "requested_unique": len(checks),
            "available": sum(bool(item["available"]) for item in checks),
            "version_verified": sum(bool(item["version_check_ok"]) for item in checks),
            "missing": sum(not item["available"] for item in checks),
            "version_check_failed": sum(bool(item["available"]) and not item["version_check_ok"] for item in checks),
        },
        "tools": checks,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("Tool preflight (local only; no installation or target traffic)")
        for item in checks:
            status = "VERSION OK" if item["version_check_ok"] else ("MISSING" if not item["available"] else "VERSION UNKNOWN")
            print(f"{status:14} {item['tool']}: {item.get('version') or item.get('error')}")
        print(json.dumps(result["summary"], ensure_ascii=False))
    return 0 if result["summary"]["missing"] == 0 and result["summary"]["version_check_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
