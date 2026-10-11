---
name: attack-port-service-discovery
description: "Identify exposed services on explicitly authorized hosts using bounded, low-impact discovery"
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [recon, ports, services, infrastructure]
tech_stack: [tcp, tls, http, nmap]
prerequisites:
  - "Written authorization explicitly permitting port/service discovery"
  - "A validated in-scope hostname or IP and approved scan limits"
chains_with: [attack-subdomain-enumeration, attack-web-recon, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills/blob/main/recon/port-service-discovery/SKILL.md"
---

# Port and Service Discovery

## When to use

Use after scope validation when exposed service inventory is part of the rules of engagement, or when web recon suggests a non-standard application endpoint. Do not scan shared infrastructure or a third-party IP merely because DNS points there.

## Prerequisites

Confirm the target, allowed port range, scan window, rate limits, and whether service/version detection is permitted. Nmap is an example tool; verify its installed version and flags. Do not use evasion or fragmentation options to bypass network controls.

## Procedure

1. **Validate the target.** Resolve the hostname, record the authorized scope entry, and confirm the IP is included or is an explicitly permitted resolution of an in-scope asset.
2. **Choose a bounded scan.** Start with the program-approved common-port set. Use a low rate and a host timeout. Expand to additional ports only when the scope and test plan permit it.
3. **Record open ports.** Preserve raw output and tool version in the local engagement workspace. An open port is an observation, not a vulnerability.
4. **Identify services conservatively.** Perform version detection only on discovered ports when allowed. Treat banners as hints; confirm protocol behavior before classifying a service.
5. **Prioritize for review.** Databases, caches, administrative interfaces, metrics endpoints, mail services, and alternate web ports may warrant focused checks, but exposure alone does not prove unauthenticated access or impact.
6. **Validate access safely.** Use non-invasive protocol handshakes or a documented read-only check. Do not attempt password guessing, data extraction, state changes, or exploitation unless separately authorized.
7. **Route findings.** Send HTTP services to web recon; send a confirmed exposed administrative surface to the relevant platform skill; send suspected unauthorized access to triage validation.
8. **Stop on instability.** Reduce activity or stop if packet loss, service degradation, blocking, or a program stop condition appears.

## Output contract

Record hostname/IP, scope evidence, scan profile, time, tool/version, open ports, service hypotheses, confidence, and next validation step. Keep raw scan output local and avoid committing target-specific artifacts.

## Verification

- Confirm every scanned address is in scope.
- Distinguish filtered, closed, and open ports.
- Confirm service identity rather than relying on port number alone.
- Recheck an interesting port with a minimal protocol-specific request.
- Do not label a service vulnerable without evidence of a security-control failure and impact.

## Pitfalls

- Treating a common port/service mapping as authoritative.
- Assuming an internet-reachable service has no authentication.
- Scanning an entire shared provider address range.
- Using high concurrency or evasion techniques without approval.
- Calling an exposed database critical without proving the relevant access boundary.

## CyberStrike integration contract

Before automation, verify the actual scope gate, network-tool registry, rate limiter, artifact writer, and finding schema. This skill must not bypass scope enforcement or turn an open port into a confirmed finding.

## Attribution

Adapted from the recon-skills port-service-discovery methodology: https://github.com/uphiago/recon-skills/blob/main/recon/port-service-discovery/SKILL.md
