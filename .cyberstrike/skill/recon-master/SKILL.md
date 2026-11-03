---
name: recon-master
description: "Route evidence-triggered reconnaissance work to eleven detailed procedures with shared scope, provenance, coverage, and specialist handoff contracts."
category: information-gathering
version: "2.4.0"
author: "CyberStrike contributors"
tags: [recon, reconnaissance, passive-recon, active-recon, osint, subdomain, dns, asn, cidr, origin-ip, vhost, ports, services, http, tls, crawling, endpoints, cms, gitlab, email-security, visual-recon, error-logs, asset-inventory, scope, evidence, tool-selection, asset-attribution, application-clustering]
signals: [scope-confirmed-root-domain, passive-subdomain-candidates, wildcard-dns, certificate-transparency-name, dns-cname-change, asn-attribution, origin-ip-candidate, cdn-edge-detected, authorized-port-range, virtual-host-routing, cms-fingerprint, application-visual-cluster, attributable-gitlab-project, organization-mail-domain, exposed-debug-or-error-log]
tech_stack: [dns, http, tls, tcp, javascript, api, cloud, browser, git, smtp]
prerequisites: []
chains_with:
  - community-tool-selection
  - target-workspace-workflow
  - attack-javascript-analysis
  - attack-finding-correlation
  - attack-shadow-api
  - attack-subdomain-takeover
  - attack-api-contract-testing
  - attack-host-header
  - attack-cache-poison
  - attack-minio-s3
  - attack-wordpress
  - attack-source-leak
  - attack-information-disclosure
  - attack-phpinfo-exposure
  - cicd-attacks
  - attack-bfla
  - attack-idor-automation
  - attack-auth-bypass
  - attack-session
---
# Recon Master — Evidence-driven Recon Router

## 1. Purpose and ownership

This skill selects and applies conditional reconnaissance techniques. It does not own engagement orchestration and it is not a checklist to execute from top to bottom.

- /recon owns engagement order, request intent, scope setup, phase progression, checkpoints, resume behavior, the canonical inventory index, and final reporting.
- The runtime scope gate owns permission for each concrete request and redirect. Discovery, DNS relationships, certificates, ASN membership, shared IPs, links, and third-party integrations never expand scope.
- recon_checkpoint owns resumable state and artifact-completion checks. RECON_PHASE_TOOL_MATRIX.md defines phase outputs and completion criteria.
- community-tool-selection and its TOOLING_CATALOG.md own tool/API/CLI/helper selection, installation, preflight, and command guidance.
- target-workspace-workflow owns canonical workspace identity, paths, persistence, and target isolation.
- attack-javascript-analysis owns JavaScript/HTML/source-map acquisition, per-file analysis, request correlation, and JS-derived candidates. Load it when JS or source-map evidence appears.
- attack-finding-correlation owns endpoint aggregation, provenance-preserving evidence graphs, deduplication, and evidence-driven specialist handoffs.

This skill owns the eleven technique procedures in RECON_CHAPTERS.md. Do not reproduce the global workflow, tool catalog, endpoint ledger, or evidence graph here.

## 2. How to use this skill

1. Read the routing table below and select only the chapter whose trigger is supported by an observed asset or evidence gap.
2. Read only that chapter in the RECON_CHAPTERS.md companion, from its numbered heading to the next numbered heading. Do not load all eleven chapters for a routine task.
3. Check the chapter's prerequisites and the persisted scope decision before any network request. Passive attribution may create candidates; active probing still requires the concrete target and method to pass the runtime policy.
4. Use registered tools and their live schemas first. Consult the one shared tool catalog only for a real capability gap. Tool names in a chapter are examples, not required commands or proof of installation.
5. Save observations into the existing canonical asset, endpoint, or evidence records. Preserve source and timestamp, distinguish observations from inferences, and do not create per-host, per-tool, or per-provider inventories.
6. Return candidate leads and a conditional next-step trigger. Do not confirm vulnerabilities or run exploit, credential, account-creation, upload, destructive, or state-changing tests from this recon skill.

## 3. Technique routing

| Chapter | Run when this evidence exists | Do not run when | Main result |
|---|---|---|---|
| 01. Cross-asset attribution and delta | Sources disagree, infrastructure is shared, dependencies have changed, or a prior snapshot exists | The relationship is name-similarity only or has no observed supporting evidence | Provenance-linked asset relationships and a freshness-aware change classification |
| 02. Subdomain enumeration | The persisted scope includes a root domain/wildcard and host coverage can add value | The scope is one exact URL and does not authorize domain expansion | Normalized hostname candidates, DNS/wildcard state, attribution confidence |
| 03. ASN and infrastructure | A confirmed organization domain or IP needs attributable infrastructure context | ASN/prefix membership would be treated as permission to scan neighbors | Ownership-confidence-rated infrastructure relationships and passive pivots |
| 04. Origin IP exposure | A confirmed application is behind a CDN/reverse proxy and edge-versus-origin behavior matters | There is no edge evidence, origin testing is out of scope, or ownership is ambiguous | Origin candidates and, only when permitted, paired edge/origin control evidence |
| 05. Port and service discovery | The exact host/IP and port range are explicitly permitted for network service discovery | Only web-host scope exists or the allowed port range is unknown | Host-attributed service records with protocol, port, banner, and confidence |
| 06. Virtual-host enumeration | Authorized infrastructure may route multiple hostnames/tenants and the target IP is attributable | Candidate IP is shared/unattributed or Host-header probes are prohibited | Vhost candidates with response clusters and attribution confidence |
| 07. CMS/component fingerprinting | First-party CMS/component signals are corroborated by markup, headers, assets, or known paths | A single weak banner or third-party widget is the only signal | CMS/component inventory and evidence-backed specialist triggers |
| 08. Visual reconnaissance | Multiple live applications need clustering or human review prioritization | Screenshots add no value or expose unnecessary personal/sensitive data | Reproducible visual clusters and review priorities |
| 09. Public GitLab reconnaissance | A GitLab namespace/project has a defensible organization ownership relationship | A public user/project is merely name-similar or unrelated | Read-only project/artifact/CI inventory and redacted disclosure leads |
| 10. Email-domain security | The mail domain is confirmed organization-owned and in scope | The domain belongs to a third party or mail testing is excluded | SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT posture with validation limits |
| 11. Error-log analysis | An in-scope application/resource exposes a plausible log, debug, or exception artifact | The resource is out of scope or collection risks excessive personal/secret data | Minimal redacted exposure evidence and impact-classification lead |

JavaScript, source maps, browser captures, and endpoint extraction are handled by attack-javascript-analysis, not by duplicating a JS procedure here. API contract drift, undocumented versions, and endpoint/method aggregation use attack-shadow-api, attack-api-contract-testing, and attack-finding-correlation when their evidence triggers are present.

## 4. Conditional specialist handoffs

Load a specialist only after its trigger is observed; chains_with is discoverability metadata, not an instruction to fan out to every linked skill.

| Observed signal | Conditional handoff |
|---|---|
| A first-party CNAME points to an unclaimed/orphaned provider resource | attack-subdomain-takeover |
| JavaScript, HTML script, source-map, or browser-extension capture appears | attack-javascript-analysis |
| API route/version is undocumented, deprecated, or differs from a contract | attack-shadow-api, then attack-api-contract-testing where a contract exists |
| Direct-origin or Host-routing behavior differs from the normal edge | attack-host-header; use attack-cache-poison only if a cache trust-boundary signal also exists |
| First-party S3/MinIO storage or content-type behavior is observed | attack-minio-s3 |
| WordPress is positively identified | attack-wordpress |
| GitLab CI configuration or build/deploy trust boundary is observed | cicd-attacks |
| A source/build artifact or source map exposes application source/configuration | attack-source-leak |
| A log/debug/exception artifact discloses internal or sensitive information | attack-information-disclosure; use attack-phpinfo-exposure only for an actual PHP configuration artifact |
| Visual evidence points to an admin-only function, tenant/object boundary, or authentication/session flow and normal HTTP evidence corroborates it | attack-bfla, attack-idor-automation, attack-auth-bypass, or attack-session according to the observed boundary |

For every handoff, pass the observed signal, canonical asset/endpoint ID, evidence references, timestamp, attribution and scope decisions, prerequisites, negative control needed, active-test permission state, exact uncertainty, and next action. The recipient must independently validate its own preconditions and impact.

## 5. Shared observation and coverage contract

Use the existing canonical workspace and evidence graph. Do not introduce a second recon queue, candidate register, delta manifest, or per-host report.

### Minimum observation fields

- Canonical asset/endpoint identity and asset type.
- Persisted scope decision and the concrete target/method checked.
- Source/provenance, observation timestamp, tool/API and version when applicable.
- Raw evidence reference only when it adds reproducibility or diagnostic value.
- Normalized observation, result state, and relevant response/DNS/TLS/service details.
- Attribution class and confidence; keep these separate from scope and vulnerability confidence.
- Negative control, limitations, next action, and related specialist trigger.

### Attribution confidence

| Level | Meaning |
|---|---|
| C0 | Unverified string, hostname, or address |
| C1 | One passive source or historical observation |
| C2 | Independent corroboration or a current attributable service response |
| C3 | Current ownership and the relevant technical relationship are corroborated with a control |

Security-impact confidence is separate. A C0–C3 asset/relationship record is not a confirmed vulnerability. A vulnerability verdict belongs to the authorized specialist validation lifecycle.

### Coverage states

Use one explicit state per source/input: not-attempted, attempted, succeeded, zero-results, failed, blocked, unavailable, or pending. Record timestamp, query/configuration, exit/response state, and a concise reason. A zero-result response is not a failed source; a failed or blocked source is not an empty result.

Keep raw candidates, normalized unique entities, scope-eligible candidates, resolved assets, live services, and first-party-attributed assets as distinct counts. Preserve multiple contributing sources on a deduplicated entity. Do not count third-party SaaS, CDN/shared-provider addresses, historical names, wildcard responses, or name-similar repositories as first-party assets without corroboration.

### Deduplication and freshness

- Hostname: normalized FQDN, preserving all source observations.
- Network service: canonical host/IP + port + transport/protocol.
- Web application: origin + corroborated application identity.
- Endpoint: normalized origin + route template + API version; HTTP methods remain separate operations.
- Public project: GitLab instance + namespace/project identity.
- Mail posture: owned domain + record/control type + selector where relevant.

Track first_seen, last_seen, and last_checked where available. Classify deltas as new, changed, stale, removed-from-current-observation, or unresolved. Missing from a later collection is not proof of deletion. Reuse prior evidence only while its input, tool/settings, and freshness remain valid.

### Stop conditions

Stop a branch on explicit exclusion, ownership/scope ambiguity, an unapproved method, unexpected sensitive data, rate limiting, instability, service degradation, or a requirement for further permission. Do not bypass access controls, register dangling resources, test discovered credentials, send unsolicited mail, or use third-party services to validate target secrets.

## 6. Shared handoff record

Use the existing correlation graph fields where available. A conditional handoff should carry:

observed_signal, bounded_hypothesis, candidate_skill, negative_control_needed, active_test_allowed, authorization basis/preconditions, canonical asset/endpoint/evidence IDs, priority rationale, exact blocker, and next_action.

A chain is a hypothesis, not a finding. Do not load every chains_with partner. Use an idempotent handoff key based on specialist + hypothesis + evidence version; reopen only when new evidence or a changed prerequisite justifies it.

## 7. Completion check

A chapter is complete only when its expected observation/output is saved and read back, counts are derived from the exact canonical records, provenance and limitations are present, and every candidate has an explicit disposition. Report complete, zero-result, blocked, unavailable, failed, and pending distinctly. A phase label, tool call, non-empty scratch file, or verbal claim is not proof that the underlying operation succeeded.

Read RECON_PHASE_TOOL_MATRIX.md for phase artifacts and TOOLING_CATALOG.md through the community-tool-selection skill for shared tools. Read only the relevant section of RECON_CHAPTERS.md for the technique being applied.
