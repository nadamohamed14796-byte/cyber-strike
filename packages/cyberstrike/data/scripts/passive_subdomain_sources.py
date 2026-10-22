#!/usr/bin/env python3
"""Collect passive subdomain observations and write one auditable JSON result.

This helper does not resolve hosts or send requests to discovered targets. It queries
crt.sh and installed passive discovery CLIs only; active recon remains a later phase.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CLI_SOURCES = ("subfinder", "amass", "assetfinder", "findomain", "sublist3r")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.I)

def normalize_host(value: str, root: str) -> str | None:
    host = value.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    host = host.strip().strip(".")
    if not host or "://" in host or "/" in host or ":" in host or "@" in host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not HOST_RE.fullmatch(host):
        return None
    if host != root and not host.endswith("." + root):
        return None
    return host

def parse_crtsh(payload: str, root: str) -> tuple[int, list[str], int]:
    records = json.loads(payload)
    if not isinstance(records, list):
        raise ValueError("crt.sh JSON response was not a list")
    hosts: list[str] = []
    rejected = 0
    raw = 0
    for record in records:
        names = record.get("name_value", "") if isinstance(record, dict) else ""
        for candidate in str(names).splitlines():
            raw += 1
            host = normalize_host(candidate, root)
            if host:
                hosts.append(host)
            else:
                rejected += 1
    return raw, hosts, rejected

def run_source(source: str, root: str, timeout: int) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    result = {"source": source, "status": "unavailable", "started_at": started, "raw_records": 0, "valid_observations": 0, "unique_hosts": 0, "rejected_records": 0, "duplicate_observations": 0, "hosts": [], "error": None, "finished_at": None}
    try:
        if source == "crt.sh":
            url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + root, "output": "json"})
            request = urllib.request.Request(url, headers={"User-Agent": "CyberStrike-passive-recon/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(20_000_001)
            if len(payload) > 20_000_000:
                raise ValueError("response exceeded 20 MB safety limit")
            raw, hosts, rejected = parse_crtsh(payload.decode("utf-8", errors="replace"), root)
        else:
            executable = shutil.which(source)
            if not executable:
                result["error"] = "executable not found on PATH"
                return result
            commands = {
                "subfinder": [executable, "-d", root, "-silent"],
                "amass": [executable, "enum", "-passive", "-d", root],
                "assetfinder": [executable, "--subs-only", root],
                "findomain": [executable, "-t", root, "-q"],
            }
            if source == "sublist3r":
                # Sublist3r requires an output filename; use a temporary path so the
                # collector still produces only its single canonical JSON artifact.
                with tempfile.TemporaryDirectory(prefix="cyberstrike-subdomains-") as tmpdir:
                    output_path = str(Path(tmpdir) / "sublist3r.txt")
                    completed = subprocess.run([executable, "-d", root, "-o", output_path], capture_output=True, text=True, timeout=timeout, check=False)
                    output = Path(output_path).read_text(encoding="utf-8", errors="replace") if Path(output_path).exists() else (completed.stdout or "")
            else:
                completed = subprocess.run(commands[source], capture_output=True, text=True, timeout=timeout, check=False)
                output = completed.stdout or ""
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            hosts = []
            rejected = 0
            for line in lines:
                host = normalize_host(line, root)
                if host:
                    hosts.append(host)
                else:
                    rejected += 1
            raw = len(lines)
            if completed.returncode != 0:
                result["status"] = "failed"
                result["error"] = (completed.stderr or f"exit status {completed.returncode}").strip()[-2000:]
                result["raw_records"] = raw
                result["valid_observations"] = len(hosts)
                result["unique_hosts"] = len(set(hosts))
                result["duplicate_observations"] = max(0, len(hosts) - len(set(hosts)))
                result["rejected_records"] = rejected
                result["hosts"] = sorted(set(hosts))
                return result
        unique = sorted(set(hosts))
        result.update(status="success" if unique else "zero-results", raw_records=raw, valid_observations=len(hosts), unique_hosts=len(unique), duplicate_observations=max(0, len(hosts) - len(unique)), rejected_records=rejected, hosts=unique)
    except subprocess.TimeoutExpired:
        result.update(status="failed", error=f"timed out after {timeout}s")
    except urllib.error.HTTPError as exc:
        result.update(status="blocked" if exc.code in (401, 403, 429) else "failed", error=f"HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError) as exc:
        result.update(status="failed", error=str(exc)[:2000])
    except Exception as exc:
        result.update(status="failed", error=f"{type(exc).__name__}: {exc}"[:2000])
    return result

def self_test() -> int:
    assert normalize_host("API.Example.com.", "example.com") == "api.example.com"
    assert normalize_host("*.api.example.com", "example.com") == "api.example.com"
    assert normalize_host("example.com", "example.com") == "example.com"
    assert normalize_host("example.com.evil.test", "example.com") is None
    assert normalize_host("https://example.com", "example.com") is None
    raw, hosts, rejected = parse_crtsh(json.dumps([{"name_value": "api.example.com\n*.www.example.com\nexample.net"}]), "example.com")
    assert (raw, sorted(set(hosts)), rejected) == (3, ["api.example.com", "www.example.com"], 1)
    print("passive_subdomain_sources self-test: PASS")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", help="root domains to query (without scheme or path)")
    parser.add_argument("--output", "-o", help="write the combined JSON result to this path (default: stdout)")
    parser.add_argument("--hosts-output", help="write the deduplicated host-only inventory to this canonical text path")
    parser.add_argument("--source", action="append", choices=("crt.sh",) + CLI_SOURCES, help="limit to a source; repeat to select multiple (default: all sources)")
    parser.add_argument("--timeout", type=int, default=90, help="timeout per source in seconds (default: 90)")
    parser.add_argument("--self-test", action="store_true", help="run offline parser/normalization checks")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.roots:
        parser.error("provide at least one root domain or use --self-test")
    roots = []
    for value in args.roots:
        root = normalize_host(value, value.lower().rstrip("."))
        if not root or root != value.lower().rstrip("."):
            parser.error(f"invalid root domain: {value!r}")
        roots.append(root)
    roots = list(dict.fromkeys(roots))
    sources = args.source or ["crt.sh", *CLI_SOURCES]
    document = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "passive-only", "roots": roots, "sources": [], "hosts": [], "counts": {}}
    observations: dict[str, list[str]] = {}
    for root in roots:
        for source in sources:
            item = run_source(source, root, max(1, args.timeout))
            item["root"] = root
            item["finished_at"] = datetime.now(timezone.utc).isoformat()
            document["sources"].append(item)
            for host in item["hosts"]:
                observations.setdefault(host, []).append(source)
    document["hosts"] = [{"host": host, "sources": sorted(set(source_list)), "observation_count": len(source_list)} for host, source_list in sorted(observations.items())]
    document["counts"] = {
        "roots": len(roots), "sources_attempted": len(document["sources"]),
        "sources_success": sum(x["status"] == "success" for x in document["sources"]),
        "sources_zero_results": sum(x["status"] == "zero-results" for x in document["sources"]),
        "sources_failed": sum(x["status"] == "failed" for x in document["sources"]),
        "sources_blocked": sum(x["status"] == "blocked" for x in document["sources"]),
        "sources_unavailable": sum(x["status"] == "unavailable" for x in document["sources"]),
        "unique_hosts": len(document["hosts"]),\n        "duplicate_observations": sum(x["duplicate_observations"] for x in document["sources"]),
    }
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(serialized, encoding="utf-8")
    else:
        sys.stdout.write(serialized)
    print("passive sources: " + json.dumps(document["counts"], sort_keys=True), file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())