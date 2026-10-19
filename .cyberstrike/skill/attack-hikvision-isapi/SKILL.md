---
name: attack-hikvision-isapi
description: "Assess in-scope Hikvision and HikCentral ISAPI surfaces, firmware exposure, and authentication boundaries through bounded read-only checks."
category: "infrastructure"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - hikvision
  - isapi
  - iot
  - camera
  - ot
  - scada
  - onvif
tech_stack:
  - hikvision
  - hikcentral
  - isapi
  - rtsp
  - onvif
  - iot
  - ot
cwe_ids:
  - CWE-200
  - CWE-284
  - CWE-862
chains_with:
  - attack-ssrf
  - attack-information-disclosure
prerequisites: []
severity_boost:
  attack-ssrf: "An HTTP pass-through feature is SSRF only when a controlled callback confirms the device initiated an outbound request; internal probing remains separately authorized."
---

# Hikvision ISAPI and Camera Management Assessment

## Objective

Inventory a scoped Hikvision/HikCentral web interface and determine whether management or streaming endpoints expose non-public information without authorization. Because these systems may control physical security or operational technology, prefer passive source review and read-only responses; do not access live video or operate devices.

## Testing Methodology

### Phase 1: Confirm ownership and operational boundaries

Verify exact device/management hostname, address, and permitted tests. Cameras, NVRs, HikCentral, ONVIF services, and RTSP listeners may be separate assets. For OT or safety-critical systems, obtain explicit written approval and a maintenance window before active requests.

### Phase 2: Fingerprint web interface and firmware

Use one bounded request to the main page and capture sanitized headers, title, certificate, and version information if publicly exposed. Confirm vendor identity using more than one signal where possible; reverse proxies and branding assets can mislead.

### Phase 3: Map API routes from public client assets

Review JavaScript files served by the in-scope interface for documented /ISAPI/ or device-resource route names. Extract route strings locally rather than fuzzing large endpoint lists. Treat a route path in JavaScript as a lead, not proof of access.

### Phase 4: Perform minimal read-only authentication checks

Choose one or two documented, low-risk status/health endpoints. Record whether anonymous requests are rejected, return an expected session-required code, or expose non-public configuration. Do not retrieve snapshots, audio/video, user/permission lists, storage configuration, recordings, or camera feeds.

### Phase 5: Review authentication and update posture

Use vendor documentation and device configuration supplied by the owner to check supported firmware, password/MFA controls, role separation, TLS, and unused services. Do not test default credentials, submit passwords, brute force, or change device settings.

### Phase 6: Handle proxy and streaming surfaces separately

If a route accepts a URL or streams content, review implementation/configuration first. Do not direct it to internal addresses, cloud metadata, external systems, or live streams. Any callback-based proof must be explicitly authorized and limited to a controlled endpoint.

### Phase 7: Record and stop at minimum proof

Capture only the response headers, error code, and a short sanitized non-sensitive field necessary to show the access boundary. Stop on instability, unexpected control behavior, video/PII exposure, or uncertainty about safety impact.

## What Constitutes a Finding

- **Candidate / lead:** a route appears in client code, version metadata is exposed, or an endpoint answers without authentication.
- **Confirmed finding:** an anonymous or lower-role request returns non-public configuration or permits a specifically scoped management action contrary to policy, with a controlled harmless proof.
- **Not a finding:** route discovery, a session-required response, public product branding, or presence of RTSP/ONVIF alone.

## Evidence Requirements

- Scoped device/management host, exact route, timestamp, status and sanitized headers/body.
- Source of route/version evidence and any vendor advisory/build mapping.
- Expected access policy and observed anonymous/test-role result.
- Avoid recording camera images, video, audio, user lists, credentials, hashes, or private configuration.

## Tools

- `curl`: a few bounded read-only requests with explicit timeout to an authorized device.
- `rg` and local text parsers: extract route names from assets already collected; do not probe every route automatically.
- Vendor firmware/security advisories: confirm affected versions and mitigations.
- Offline HTML/JavaScript parsers: inventory delivered assets without executing active content.

Verify `curl --version`. Official docs: https://curl.se/docs/ and the manufacturer's current security advisory/firmware pages. Do not attempt default-password checks, configuration changes, or state-changing device operations without explicit authorization.

## ISAPI Surface and Safety Matrix

| Surface | Low-risk check | Evidence standard |
|---|---|---|
| Web UI / firmware | Main page, response metadata, documented version field | Two identity signals where practical; vendor advisory corroboration |
| ISAPI health/status | One documented read-only endpoint | Confirm whether only non-sensitive health data is public |
| Camera/stream endpoints | Review route names and authorization policy | Do not fetch live video or snapshots as default proof |
| User/permission routes | Source/config review or synthetic lab fixture | No production user/role enumeration |
| Storage/recording routes | Review docs, role policy, firmware | Do not list or download recordings/configuration |
| HTTP pass-through/proxy | Review code/config; controlled lab callback only if approved | No internal port, metadata, or third-party target probes |
| ONVIF/RTSP | Record service fingerprint only | No media viewing or control commands |

**Mitigation:** update firmware, disable unused interfaces, isolate cameras/management from the internet, require unique credentials and role checks, enable secure transport, and audit access to streams and settings.

## Verification and False Positives

- A route discovered in a JavaScript bundle may be stale, unused, or protected by session middleware.
- A vendor-specific error code often indicates authentication is required rather than a vulnerability.
- Device health endpoints and firmware strings may be intentionally public; evaluate sensitivity and policy.
- A port or login page being reachable is not an authorization bypass.
- Stop before default credential tests, camera feeds, audio/video, settings changes, firmware upload, internal SSRF, or any physical/operational effect.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful, authorized read-only hypotheses. Continue while a distinct check can change the conclusion; deduplicate equivalent metadata checks and stop when evidence resolves the question, relevant branches are exhausted, prerequisites are unavailable, or scope/safety requires stopping. Never access live media or operate physical/OT functions as proof.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

1. Proceed only for explicitly authorized devices/labs; inventory reachable model, firmware, and ISAPI response behavior with read-only requests before considering any test.
2. Compare anonymous and controlled low-privilege behavior for documented read-only device/config endpoints; avoid default-password spraying, configuration writes, firmware changes, and reboot operations.
3. Treat firmware/version fingerprints as leads only; correlate exact model and release with vendor advisories and determine whether the affected feature is reachable in this deployment.
4. Use a synthetic device record or harmless configuration marker to validate an access-control defect. Do not retrieve video, credentials, private feeds, or other people's camera data.
5. Record exact endpoint, firmware evidence, expected permission, actual disclosure/action, and safe remediation such as patching, network isolation, and disabling unnecessary services.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [uphiago/recon-skills — SCADA/Hikvision ISAPI](https://github.com/uphiago/recon-skills/blob/main/recon/scada-hikvision-isapi/SKILL.md) — merged protocol-specific source.

- [uphiago/recon-skills — scada-hikvision-isapi](https://github.com/uphiago/recon-skills/tree/main/recon/scada-hikvision-isapi)
- [Hikvision support and security advisories](https://www.hikvision.com/en/support/)
- [ONVIF specifications](https://www.onvif.org/profiles/)


## Targeted quality-loop enrichment (2026-10-19)

### Device-management safety and evidence
Treat camera/control endpoints as operational technology: verify ownership and written permission first, prefer passive firmware/banner evidence and read-only metadata, and avoid PTZ movement, reboot, account changes, recording deletion, or firmware mutation. Distinguish vendor/version identification from a reachable sensitive action, and redact device identifiers, credentials, image/video content, and network details not needed for reproduction. Confirm whether the path is an intended public live view or an administrative control plane. Only chain an authentication defect to information exposure when controlled evidence demonstrates protected device data; do not collect feeds or access other users' cameras.


## Offline route inventory from first-party assets

If the in-scope web UI serves JavaScript, inspect downloaded assets locally to identify route strings without probing each path. Keep the asset source and timestamp with the result.

```bash
rg -o --no-filename '/ISAPI/[A-Za-z0-9_./{}?-]+' ./authorized-assets/ | sort -u
```

Treat extracted routes as documentation leads only. Do not automatically request each route or fetch snapshots, video, recordings, user lists, or configuration. Select a documented non-sensitive status route only when the engagement explicitly permits it.

### Evidence fields

Record device_family, model_signal, firmware_signal_source, vendor_advisory, route_source_asset, route_name_only, auth_policy_expected, read_only_response_ref, sensitive_data_excluded, test_environment, and cleanup_status. Keep physical/operational impact separate from web access-control impact.
