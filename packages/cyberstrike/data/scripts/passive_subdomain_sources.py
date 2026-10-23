#!/usr/bin/env python3
"""Collect passive subdomain observations and write one auditable JSON result.

This helper does not resolve hosts or send requests to discovered targets. It queries
crt.sh, CertSpotter, AlienVault OTX passive DNS, and installed passive discovery CLIs; active recon remains a later phase.
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
API_SOURCES = ("crt.sh", "certspotter", "otx_passive_dns")
ALL_SOURCES = (*API_SOURCES, *CLI_SOURCES)
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.I)

def default_source_selection() -> list[str]:
    """Pick independent public APIs plus one installed primary CLI, not every equivalent CLI."""
    selected = list(API_SOURCES)
    primary_cli = next((source for source in CLI_SOURCES if shutil.which(source)), None)
    if primary_cli:
        selected.append(primary_cli)
    return selected


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
    hosts: list[str] = []
    raw = 0
    rejected = 0

    def save_partial(status: str, error: str) -> dict:
        unique = sorted(set(hosts))
        result.update(
            status=status,
            raw_records=raw,
            valid_observations=len(hosts),
            unique_hosts=len(unique),
            duplicate_observations=max(0, len(hosts) - len(unique)),
            rejected_records=rejected,
            hosts=unique,
            error=error[:2000],
        )
        return result

    try:
        if source == "crt.sh":
            url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + root, "output": "json"})
            request = urllib.request.Request(url, headers={"User-Agent": "CyberStrike-passive-recon/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(20_000_001)
            if len(payload) > 20_000_000:
                raise ValueError("response exceeded 20 MB safety limit")
            raw, hosts, rejected = parse_crtsh(payload.decode("utf-8", errors="replace"), root)

        elif source == "certspotter":
            # CertSpotter exposes unauthenticated CT search with a small rate budget.
            # Follow the documented after=issuance-id cursor until exhaustion,
            # a repeated cursor, a parser error, or a service/rate-limit response.
            cursor: str | None = None
            seen_cursors: set[str] = set()
            while True:
                pairs: list[tuple[str, str]] = [
                    ("domain", root),
                    ("include_subdomains", "true"),
                    ("expand", "dns_names"),
                ]
                if cursor:
                    pairs.append(("after", cursor))
                url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(pairs)
                headers = {"User-Agent": "CyberStrike-passive-recon/1.0", "Accept": "application/json"}
                token = os.environ.get("CERTSPOTTER_API_KEY")
                if token:
                    headers["Authorization"] = "Bearer " + token
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    payload = response.read(20_000_001)
                if len(payload) > 20_000_000:
                    raise ValueError("CertSpotter response page exceeded 20 MB safety limit")
                records = json.loads(payload.decode("utf-8", errors="replace"))
                if not isinstance(records, list):
                    raise ValueError("CertSpotter JSON response was not a list")
                if not records:
                    break
                for record in records:
                    if not isinstance(record, dict) or not isinstance(record.get("dns_names"), list):
                        raise ValueError("CertSpotter issuance record is missing dns_names")
                    for candidate in record["dns_names"]:
                        raw += 1
                        host = normalize_host(str(candidate), root)
                        if host:
                            hosts.append(host)
                        else:
                            rejected += 1
                next_cursor = records[-1].get("id")
                if not isinstance(next_cursor, (str, int)) or not str(next_cursor):
                    raise ValueError("CertSpotter page has no issuance id; cannot safely continue pagination")
                cursor = str(next_cursor)
                if cursor in seen_cursors:
                    raise ValueError("CertSpotter repeated a pagination cursor")
                seen_cursors.add(cursor)

        elif source == "otx_passive_dns":
            url = "https://otx.alienvault.com/api/v1/indicators/domain/" + urllib.parse.quote(root, safe="") + "/passive_dns"
            headers = {"User-Agent": "CyberStrike-passive-recon/1.0", "Accept": "application/json"}
            token = os.environ.get("OTX_API_KEY")
            if token:
                headers["X-OTX-API-KEY"] = token
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(20_000_001)
            if len(payload) > 20_000_000:
                raise ValueError("OTX response exceeded 20 MB safety limit")
            data = json.loads(payload.decode("utf-8", errors="replace"))
            records = data.get("passive_dns") if isinstance(data, dict) else None
            if not isinstance(records, list):
                raise ValueError("OTX JSON response was missing passive_dns records")
            raw = len(records)
            for record in records:
                candidate = record.get("hostname", "") if isinstance(record, dict) else ""
                host = normalize_host(str(candidate), root)
                if host:
                    hosts.append(host)
                else:
                    rejected += 1

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
            for line in lines:
                raw += 1
                host = normalize_host(line, root)
                if host:
                    hosts.append(host)
                else:
                    rejected += 1
            if completed.returncode != 0:
                return save_partial("failed", (completed.stderr or f"exit status {completed.returncode}").strip())

        unique = sorted(set(hosts))
        result.update(status="success" if unique else "zero-results", raw_records=raw, valid_observations=len(hosts), unique_hosts=len(unique), duplicate_observations=max(0, len(hosts) - len(unique)), rejected_records=rejected, hosts=unique)
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        for line in str(partial).splitlines():
            if not line.strip():
                continue
            raw += 1
            host = normalize_host(line, root)
            if host:
                hosts.append(host)
            else:
                rejected += 1
        return save_partial("failed", f"timed out after {timeout}s")
    except urllib.error.HTTPError as exc:
        return save_partial("blocked" if exc.code in (401, 403, 429) else "failed", f"HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError) as exc:
        return save_partial("failed", str(exc))
    except Exception as exc:
        return save_partial("failed", f"{type(exc).__name__}: {exc}")
    return result

def self_test() -> int:
    raw, hosts, rejected = parse_crtsh(json.dumps([{"name_value": "api.example.com\n*.www.example.com\nexample.net"}]), "example.com")
    assert (raw, sorted(set(hosts)), rejected) == (3, ["api.example.com", "www.example.com"], 1)
    assert normalize_host("API.Example.com.", "example.com") == "api.example.com"
    assert normalize_host("*.api.example.com", "example.com") == "api.example.com"
    assert normalize_host("example.com", "example.com") == "example.com"
    assert normalize_host("example.com.evil.test", "example.com") is None
    assert normalize_host("https://example.com", "example.com") is None

    # Exercise adapters, resumable persistence, and output integrity offline.
    original_path = os.environ.get("PATH", "")
    original_calls = os.environ.get("CYBERSTRIKE_TEST_CALLS")
    original_empty = os.environ.get("CYBERSTRIKE_TEST_EMPTY")
    with tempfile.TemporaryDirectory(prefix="cyberstrike-source-test-") as tmpdir:
        bin_dir = Path(tmpdir) / "bin"
        bin_dir.mkdir()
        calls_path = Path(tmpdir) / "source-calls.txt"
        os.environ["CYBERSTRIKE_TEST_CALLS"] = str(calls_path)
        stub = [
            "#!/usr/bin/env python3",
            "import pathlib, sys, os",
            "args = sys.argv[1:]",
            "calls = pathlib.Path(os.environ['CYBERSTRIKE_TEST_CALLS'])",
            "calls.write_text((calls.read_text() if calls.exists() else '') + 'x', encoding='utf-8')",
            "rows = [] if os.environ.get(\'CYBERSTRIKE_TEST_EMPTY\') == \'1\' else [\'api.example.com\', \'API.example.com.\', \'*.www.example.com\', \'outside.test\', \'invalid host\']",
            "if '-o' in args:",
            "    pathlib.Path(args[args.index('-o') + 1]).write_text('\\n'.join(rows) + '\\n', encoding='utf-8')",
            "else:",
            "    print('\\n'.join(rows))",
        ]
        for source in CLI_SOURCES:
            executable = bin_dir / source
            executable.write_text("\n".join(stub) + "\n", encoding="utf-8")
            executable.chmod(0o755)
        os.environ["PATH"] = str(bin_dir) + os.pathsep + original_path
        try:
            for source in CLI_SOURCES:
                result = run_source(source, "example.com", 5)
                assert result["status"] == "success", (source, result)
                assert result["raw_records"] == 5, (source, result)
                assert result["valid_observations"] == 3, (source, result)
                assert result["unique_hosts"] == 2, (source, result)
                assert result["duplicate_observations"] == 1, (source, result)
                assert result["rejected_records"] == 2, (source, result)

            # Test the CertSpotter and OTX HTTP adapters without making network requests.
            original_urlopen = urllib.request.urlopen
            api_requests: list[str] = []

            class FakeResponse:
                def __init__(self, value):
                    self.payload = json.dumps(value).encode("utf-8")

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def read(self, size=-1):
                    return self.payload if size < 0 else self.payload[:size]

            def fake_urlopen(request, timeout):
                url = request.full_url
                api_requests.append(url)
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                if parsed.netloc == "api.certspotter.com":
                    if "after" in query:
                        return FakeResponse([])
                    return FakeResponse([{
                        "id": "issuer-1",
                        "dns_names": ["api.example.com", "*.www.example.com", "example.net"],
                    }])
                if parsed.netloc == "otx.alienvault.com":
                    return FakeResponse({
                        "count": 2,
                        "passive_dns": [
                            {"hostname": "api.example.com", "record_type": "A"},
                            {"hostname": "outside.test", "record_type": "A"},
                        ],
                    })
                raise AssertionError("unexpected test URL: " + url)

            urllib.request.urlopen = fake_urlopen
            try:
                certspotter = run_source("certspotter", "example.com", 5)
                otx = run_source("otx_passive_dns", "example.com", 5)
            finally:
                urllib.request.urlopen = original_urlopen
            assert len(api_requests) == 3, api_requests  # two CertSpotter pages plus OTX
            assert certspotter["status"] == "success", certspotter
            assert certspotter["raw_records"] == 3 and certspotter["unique_hosts"] == 2, certspotter
            assert certspotter["rejected_records"] == 1, certspotter
            assert certspotter["hosts"] == ["api.example.com", "www.example.com"], certspotter
            assert otx["status"] == "success", otx
            assert otx["raw_records"] == 2 and otx["unique_hosts"] == 1, otx
            assert otx["rejected_records"] == 1 and otx["hosts"] == ["api.example.com"], otx

            # Exclude adapter preflight invocations from resume assertions below.
            calls_path.write_text("", encoding="utf-8")
            original_argv = sys.argv[:]
            json_path = Path(tmpdir) / "subdomain-sources.json"
            hosts_path = Path(tmpdir) / "subdomains.txt"
            args = [sys.argv[0], "example.com", "--source", "subfinder", "--output", str(json_path), "--hosts-output", str(hosts_path)]
            try:
                sys.argv = args[:]
                assert main() == 0
                # A normal resume preserves a successful source and does not invoke it again.
                sys.argv = args[:]
                assert main() == 0
                assert calls_path.read_text(encoding="utf-8") == "x"
                # Explicit retry is the only way to rerun a terminal source result.
                sys.argv = args[:] + ["--retry-source", "subfinder"]
                os.environ["CYBERSTRIKE_TEST_EMPTY"] = "1"
                assert main() == 0
                assert calls_path.read_text(encoding="utf-8") == "xx"
                # Selecting a previously skipped alternative makes only that source
                # eligible; no successful or failed peer is rerun by implication.
                sys.argv = [sys.argv[0], "example.com", "--source", "amass", "--output", str(json_path), "--hosts-output", str(hosts_path)]
                assert main() == 0
                assert calls_path.read_text(encoding="utf-8") == "xxx"
            finally:
                sys.argv = original_argv

            saved = json.loads(json_path.read_text(encoding="utf-8"))
            saved_hosts = hosts_path.read_text(encoding="utf-8").splitlines()
            assert [item["host"] for item in saved["hosts"]] == saved_hosts
            assert saved_hosts == ["api.example.com", "www.example.com"]
            assert saved["counts"]["sources_attempted"] == 1
            assert saved["counts"]["sources_pending"] == 0
            assert saved["counts"]["sources_skipped"] == 0
            assert saved["counts"]["sources_not_selected"] == len(ALL_SOURCES) - 2
            assert saved["counts"]["sources_zero_results"] == 2
            assert saved["run_status"] == "complete"
            amass_record = next(item for item in saved["sources"] if item["root"] == "example.com" and item["source"] == "amass")
            assert amass_record["status"] == "zero-results"
            assert amass_record["attempt_count"] == 1
            assert amass_record.get("skipped_by_selection") is None
            source_record = next(item for item in saved["sources"] if item["root"] == "example.com" and item["source"] == "subfinder")
            assert source_record["attempt_count"] == 2
            assert len(source_record["attempt_history"]) == 2
            assert [attempt["status"] for attempt in source_record["attempt_history"]] == ["success", "zero-results"]
            assert source_record["hosts"] == []
            assert source_record["attempt_history"][0]["hosts"] == ["api.example.com", "www.example.com"]
            api_record = next(item for item in saved["hosts"] if item["host"] == "api.example.com")
            assert api_record["roots"] == ["example.com"]
            assert api_record["observations"] == [{"root": "example.com", "source": "subfinder"}]
        finally:
            os.environ["PATH"] = original_path
            if original_calls is None:
                os.environ.pop("CYBERSTRIKE_TEST_CALLS", None)
            else:
                os.environ["CYBERSTRIKE_TEST_CALLS"] = original_calls
            if original_empty is None:
                os.environ.pop("CYBERSTRIKE_TEST_EMPTY", None)
            else:
                os.environ["CYBERSTRIKE_TEST_EMPTY"] = original_empty
    print("passive_subdomain_sources self-test: PASS (normalization, 3 HTTP APIs, 5 CLI adapters, atomic outputs, resume, and retry)")
    return 0

def atomic_write_text(destination: Path, content: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, prefix="." + destination.name + ".", suffix=".tmp", delete=False) as handle:
            temp_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, destination)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def refresh_inventory(document: dict) -> None:
    source_records = document["sources"]
    document["hosts"] = []
    observations: dict[str, list[dict[str, str]]] = {}
    for item in source_records:
        root = item.get("root")
        source = item.get("source")
        if not isinstance(root, str) or not isinstance(source, str):
            continue
        host_observations = {host for host in item.get("hosts", []) if isinstance(host, str)}
        # A retry may return fewer names or zero results. Preserve hostnames from
        # earlier saved attempts as historical observations instead of erasing them.
        for attempt in item.get("attempt_history", []):
            if isinstance(attempt, dict):
                host_observations.update(host for host in attempt.get("hosts", []) if isinstance(host, str))
        for host in host_observations:
            observations.setdefault(host, []).append({"root": root, "source": source})
    document["hosts"] = [
        {
            "host": host,
            "roots": sorted({item["root"] for item in source_observations}),
            "sources": sorted({item["source"] for item in source_observations}),
            "observations": sorted(source_observations, key=lambda item: (item["root"], item["source"])),
            "observation_count": len(source_observations),
        }
        for host, source_observations in sorted(observations.items())
    ]
    counts = {
        "roots": len(document["roots"]),
        "sources_attempted": sum(int(item.get("attempt_count", 0)) > 0 for item in source_records),
        "sources_pending": sum(item.get("status") == "pending" for item in source_records),
        "sources_not_started": sum(item.get("status") == "pending" and int(item.get("attempt_count", 0)) == 0 for item in source_records),
        "sources_running_or_interrupted": sum(item.get("status") == "pending" and int(item.get("attempt_count", 0)) > len(item.get("attempt_history", [])) for item in source_records),
        "sources_success": sum(item.get("status") == "success" for item in source_records),
        "sources_zero_results": sum(item.get("status") == "zero-results" for item in source_records),
        "sources_failed": sum(item.get("status") == "failed" for item in source_records),
        "sources_blocked": sum(item.get("status") == "blocked" for item in source_records),
        "sources_unavailable": sum(item.get("status") == "unavailable" for item in source_records),
        "sources_skipped": sum(item.get("status") == "skipped" and item.get("skipped_by_selection") is not True for item in source_records),
        "sources_not_selected": sum(item.get("status") == "skipped" and item.get("skipped_by_selection") is True for item in source_records),
        "unique_hosts": len(document["hosts"]),
        "duplicate_observations": sum(sum(int(attempt.get("duplicate_observations", 0)) for attempt in item.get("attempt_history", []) if isinstance(attempt, dict)) if item.get("attempt_history") else int(item.get("duplicate_observations", 0)) for item in source_records),
    }
    document["counts"] = counts
    if counts["sources_pending"]:
        document["run_status"] = "running"
    elif any(counts[key] for key in ("sources_failed", "sources_blocked", "sources_unavailable", "sources_skipped")):
        document["run_status"] = "finished_with_gaps"
    else:
        document["run_status"] = "complete"
    document["updated_at"] = datetime.now(timezone.utc).isoformat()


def persist_snapshot(document: dict, output_path: Path | None, hosts_path: Path | None) -> None:
    refresh_inventory(document)
    # JSON is the resume ledger and is written last. On startup, rebuild TXT from
    # that ledger so a crash between the two atomic replacements self-heals.
    if hosts_path is not None:
        atomic_write_text(hosts_path, "".join(item["host"] + "\n" for item in document["hosts"]))
    if output_path is not None:
        atomic_write_text(output_path, json.dumps(document, indent=2, sort_keys=True) + "\n")


def append_interrupted_attempt(item: dict) -> list[dict]:
    """Preserve a started source attempt when its process ended before a terminal save."""
    history = list(item.get("attempt_history", []))
    if item.get("status") == "pending" and item.get("started_at") and not item.get("finished_at"):
        history.append({
            "attempt": int(item.get("attempt_count", len(history) + 1)),
            "started_at": item["started_at"],
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": "interrupted",
            "raw_records": int(item.get("raw_records", 0)),
            "valid_observations": int(item.get("valid_observations", 0)),
            "unique_hosts": int(item.get("unique_hosts", 0)),
            "duplicate_observations": int(item.get("duplicate_observations", 0)),
            "rejected_records": int(item.get("rejected_records", 0)),
            "error": "Previous invocation ended before a terminal source result was persisted",
            "hosts": sorted(set(item.get("hosts", []))),
        })
    return history


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", help="root domains to query (without scheme or path)")
    parser.add_argument("--output", "-o", help="canonical JSON ledger; pass the same path to resume")
    parser.add_argument("--hosts-output", help="canonical deduplicated host-only inventory text path")
    parser.add_argument("--source", action="append", choices=ALL_SOURCES, help="run/ensure only these sources; repeat to select multiple")
    parser.add_argument("--retry-source", action="append", choices=ALL_SOURCES, help="explicitly retry completed/failed records for a source; repeatable")
    parser.add_argument("--timeout", type=int, default=90, help="timeout per source in seconds (default: 90)")
    parser.add_argument("--fresh", action="store_true", help="start a new ledger in the same canonical paths instead of resuming an existing one")
    parser.add_argument("--self-test", action="store_true", help="run offline parser, adapter, persistence, and resume checks")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.roots:
        parser.error("provide at least one root domain or use --self-test")

    roots: list[str] = []
    for value in args.roots:
        root = normalize_host(value, value.lower().rstrip("."))
        if not root or root != value.lower().rstrip("."):
            parser.error(f"invalid root domain: {value!r}")
        roots.append(root)
    roots = list(dict.fromkeys(roots))
    if not roots:
        parser.error("no valid root domains")
    if args.output and not args.hosts_output:
        parser.error("--hosts-output is required with --output so the two canonical inventories stay in sync")
    if args.hosts_output and not args.output:
        parser.error("--output is required with --hosts-output so source status remains resumable")

    output_path = Path(args.output).expanduser().resolve() if args.output else None
    hosts_path = Path(args.hosts_output).expanduser().resolve() if args.hosts_output else None
    default_sources = list(ALL_SOURCES)
    selected_sources = list(dict.fromkeys(args.source or default_source_selection()))
    retry_sources = set(args.retry_source or [])
    selected_sources = list(dict.fromkeys([*selected_sources, *retry_sources]))

    document: dict
    if output_path is not None and output_path.exists() and not args.fresh:
        try:
            loaded = json.loads(output_path.read_text(encoding="utf-8"))
        except Exception as exc:
            parser.error(f"existing resume ledger is unreadable; refusing to overwrite it ({type(exc).__name__}: {exc})")
        if not isinstance(loaded, dict) or loaded.get("schema_version") != 1 or not isinstance(loaded.get("roots"), list) or not isinstance(loaded.get("sources"), list):
            parser.error("existing resume ledger has an unsupported schema; use --fresh to replace it")
        existing_roots = loaded["roots"]
        if set(existing_roots) != set(roots) or len(existing_roots) != len(roots):
            parser.error("provided roots differ from the saved ledger; preserve one canonical scope per output path or pass --fresh intentionally")
        if not all(isinstance(item, dict) and isinstance(item.get("root"), str) and isinstance(item.get("source"), str) and item.get("status") in {"pending", "success", "zero-results", "failed", "unavailable", "blocked", "skipped"} for item in loaded["sources"]):
            parser.error("existing resume ledger contains invalid source records; refusing to overwrite it")
        document = loaded
        # Preserve the original root ordering from the ledger to keep stable artifacts.
        roots = document["roots"]
    else:
        document = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "passive-only",
            "roots": roots,
            "sources": [],
            "hosts": [],
            "counts": {},
            "run_status": "running",
        }

    # Merge an explicit source subset into the existing worklist without discarding
    # earlier records; normal full runs add all five CLI sources and crt.sh.
    indexed = {(item["root"], item["source"]): item for item in document["sources"]}
    for root in roots:
        # Always record the full default worklist; --source selects what this invocation
        # executes, not what the run is allowed to claim it covered.
        for source in default_sources:
            key = (root, source)
            if key not in indexed:
                item = {
                    "root": root,
                    "source": source,
                    "status": "pending",
                    "started_at": None,
                    "finished_at": None,
                    "raw_records": 0,
                    "valid_observations": 0,
                    "unique_hosts": 0,
                    "duplicate_observations": 0,
                    "rejected_records": 0,
                    "hosts": [],
                    "error": None,
                }
                document["sources"].append(item)
                indexed[key] = item
            elif source in retry_sources:
                item = indexed[key]
                item.update({
                    "status": "pending",
                    "started_at": None,
                    "finished_at": None,
                    "raw_records": 0,
                    "valid_observations": 0,
                    "unique_hosts": 0,
                    "duplicate_observations": 0,
                    "rejected_records": 0,
                    "hosts": [],
                    "error": None,
                })
                item.pop("skipped_by_selection", None)
            elif source in selected_sources and item.get("skipped_by_selection") is True:
                # A source intentionally skipped in an earlier run becomes eligible
                # automatically if later selected; successful/failed attempts remain
                # terminal until an explicit --retry-source is supplied.
                item.update({
                    "status": "pending",
                    "started_at": None,
                    "finished_at": None,
                    "error": None,
                })
                item.pop("skipped_by_selection", None)

    if not args.fresh and retry_sources:
        # A retry should not mark a source in a root as complete if it was omitted
        # from the current explicit selected list; selected_sources already contains
        # every explicitly requested retry source.
        pass

    # A selected worklist must not leave unselected sources looking like unfinished
    # jobs. Save an explicit skipped outcome so the run can finish honestly with gaps;
    # if one of these sources is selected in a later invocation, it becomes pending.
    for item in document["sources"]:
        if item.get("source") in selected_sources or item.get("status") != "pending":
            continue
        history = append_interrupted_attempt(item)
        item["attempt_history"] = history
        source = item["source"]
        if source in CLI_SOURCES and not shutil.which(source):
            reason = f"{source} is not installed and was not selected automatically; install it only if needed coverage is missing, then select it explicitly"
        elif source in CLI_SOURCES:
            reason = f"{source} was not selected automatically because an equivalent primary CLI was preferred; select it explicitly if it can add independent coverage"
        else:
            reason = f"{source} was not selected for this invocation; select it explicitly if its distinct coverage is needed"
        item.update({
            "status": "skipped",
            "started_at": None,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "error": reason,
            "skipped_by_selection": True,
        })

    persist_snapshot(document, output_path, hosts_path)
    # Only pending records for the selected source set run. Prior terminal records
    # remain available as evidence and are never rerun implicitly.
    for item in document["sources"]:
        if item.get("root") not in roots or item.get("source") not in selected_sources or item.get("status") != "pending":
            continue
        history = append_interrupted_attempt(item)
        attempt_number = int(item.get("attempt_count", 0)) + 1
        started_at = datetime.now(timezone.utc).isoformat()
        item["attempt_history"] = history
        item["attempt_count"] = attempt_number
        item["started_at"] = started_at
        item["finished_at"] = None
        # Persist that an attempt is in progress before launching its process.
        persist_snapshot(document, output_path, hosts_path)
        completed = run_source(item["source"], item["root"], max(1, args.timeout))
        finished_at = datetime.now(timezone.utc).isoformat()
        completed["root"] = item["root"]
        completed["source"] = item["source"]
        completed["started_at"] = started_at
        completed["finished_at"] = finished_at
        completed["attempt_count"] = attempt_number
        completed["attempt_history"] = history + [{
            "attempt": attempt_number,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": completed["status"],
            "raw_records": int(completed.get("raw_records", 0)),
            "valid_observations": int(completed.get("valid_observations", 0)),
            "unique_hosts": int(completed.get("unique_hosts", 0)),
            "duplicate_observations": int(completed.get("duplicate_observations", 0)),
            "rejected_records": int(completed.get("rejected_records", 0)),
            "error": completed.get("error"),
            "hosts": sorted(set(completed.get("hosts", []))),
        }]
        item.clear()
        item.update(completed)
        persist_snapshot(document, output_path, hosts_path)

    # A subset run leaves other known source pairs as saved evidence and reports its
    # coverage honestly. The run is complete only when every entry is terminal.
    persist_snapshot(document, output_path, hosts_path)
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if output_path is None:
        sys.stdout.write(serialized)
    print("passive sources: " + json.dumps(document["counts"], sort_keys=True), file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())