---
name: attack-cloud-misconfig
description: "Review cloud IAM, storage, network exposure, workload identity, and logging configuration for excessive access using read-only, owner-approved checks."
category: "cloud"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - cloud
  - iam
  - misconfiguration
  - storage
  - network
  - logging
tech_stack:
  - aws
  - azure
  - gcp
  - iam
  - object-storage
  - kubernetes
cwe_ids:
  - CWE-284
  - CWE-732
  - CWE-200
  - CWE-668
chains_with:
  - cloud-assessment
  - aws-postexploit
  - azure-postexploit
  - gcp-postexploit
  - attack-minio-s3
  - attack-ssrf
prerequisites: []
severity_boost: {}
---

# Cloud Configuration and Permission Assessment

## Objective

Identify cloud control-plane and data-plane configuration that grants access beyond the intended role or tenant. Prefer static policy review, provider-native read-only audits, and synthetic resources; do not retrieve secrets, enumerate customer data, or modify live infrastructure.

## Testing Methodology

### Phase 1: Confirm account and resource scope

Record the cloud account/project/subscription, regions, resource identifiers, permitted read-only roles, and exclusions. A public hostname or DNS record does not authorize testing the underlying account. Separate cloud provider endpoints from the application asset in the program scope.

### Phase 2: Review IAM trust and least privilege

Inspect role trust policies, wildcard actions/resources, cross-account principals, service-account impersonation, access-key age/rotation policy, and privilege paths using provider documentation. Avoid assuming a policy is exploitable without an applicable principal and reachable permission chain.

### Phase 3: Assess storage and data access

Review bucket/container access policies, public-access blockers, object ownership, signed URL lifetimes, and encryption settings. Use a tester-owned synthetic object or provider access-analyzer output. Do not list or download real customer objects to demonstrate a permission issue.

### Phase 4: Check network exposure and management planes

Review security groups/firewall rules, public endpoints, private-link settings, management consoles, and administrative protocols. Validate only the specific in-scope resource; do not sweep public ranges or pivot into linked tenant/network assets.

### Phase 5: Review workload identity and metadata boundaries

Inspect pod/task/service identities, workload identity bindings, instance metadata protections, secret mounts, and trust policies from configuration. Do not request cloud metadata credentials or use an SSRF to retrieve access tokens in production. Use lab simulation or provider policy analysis for escalation paths.

### Phase 6: Validate logging, audit, and encryption controls

Review cloud audit configuration, public logs, key policies, default encryption, retention, and sensitive diagnostic paths. Distinguish a missing setting from a policy violation or data exposure under the program's severity rules.

### Phase 7: Confirm and recommend least change

Create a minimal policy diff showing the excess permission and a regression test using a synthetic principal/resource. Do not apply changes to production; suggest a narrowly scoped fix and rerun read-only analysis after the owner applies it.

## What Constitutes a Finding

- **Candidate / lead:** wildcard IAM policy, public storage, overly broad security group, cross-account trust, public management endpoint, or missing audit setting.
- **Confirmed configuration issue:** the effective policy grants a documented unintended capability or a synthetic resource is accessible to a principal outside intended trust boundaries.
- **Impact-qualified:** show the smallest relevant allowed/denied result or policy evaluation; avoid accessing real data or attempting escalation in production.
- **Not a finding alone:** public DNS, a provider's public API endpoint, a default encryption flag, or a static policy string without an applicable principal/resource path.

## Evidence Requirements

- Account/project/subscription and exact in-scope resource ID (sanitized where public disclosure is restricted).
- Effective-policy snapshot or provider-native analysis with principal/action/resource/context.
- Synthetic object or controlled role comparison, timestamp, and expected policy.
- Redact access keys, secret values, customer data, role tokens, and signed URL credentials.

## Tools

- **AWS IAM Access Analyzer / AWS Config:** evaluate reachable policy and resource exposure.
- **Azure Policy / Defender for Cloud:** review scoped configuration findings.
- **GCP Policy Analyzer / Security Command Center:** analyze effective permissions and resource exposure.
- **Cloud provider CLI in read-only mode:** inspect only enumerated scoped resources.
- **IaC scanners:** review Terraform/CloudFormation/Bicep/Kubernetes manifests locally.

## Cloud Misconfiguration Matrix

| Area | Review | Confirmation |
|---|---|---|
| IAM | Wildcards, role trust, cross-account access | Effective principal has unintended action on a test/specified resource |
| Storage | Public access, object policy, signed URL scope | Synthetic private object is readable outside policy |
| Network | Public ingress, admin ports, missing private path | Exact in-scope service exposed contrary to baseline |
| Workload identity | Excess service-account permissions, metadata access | Policy or lab proof confirms the workload's unintended capability |
| Secrets | Hardcoded keys, wide secret read policies | Show name/location and redacted value only; never use the secret |
| Logs/audit | Public logs, missing critical audit configuration | Demonstrate unintended disclosure or policy violation |
| Encryption | Key-policy and at-rest settings | Prove affected data/resource context; don't overstate missing flags |

**Mitigation:** least-privilege IAM, narrowly scoped trust, private data endpoints, provider public-access protections, managed workload identity, secret rotation, encryption/key policies, and continuous policy checks.

## Verification and False Positives

- Cloud roles may intentionally include wildcard resources for provider-managed service actions; verify the effective scope and principal.
- A resource's public DNS or login page is not proof of public data access.
- Missing logging/encryption alone may be informational unless it violates policy or meaningfully changes risk.
- Never dump storage, enumerate real data, retrieve metadata credentials, create access keys, or modify production configuration.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

1. Define the authorized cloud account, subscription/project, region, and role before running checks; inventory only resources visible to that approved identity and preserve account/resource IDs as provenance.
2. Start with read-only posture checks for identity policy, public access settings, network exposure, audit logging, encryption, and secret-handling configuration; compare each result with vendor guidance and the intended architecture.
3. Where public data access is suspected, use a purpose-built benign canary object or metadata-only permission check. Do not list or download unrelated customer data to prove exposure.
4. Validate effective permissions from the actual test principal and resource policy together; inherited organization controls, public-but-empty resources, and intentionally public assets are important alternative explanations.
5. Record the smallest reproducible misconfiguration, effective reachability, exact exposed capability, and least-change remediation; re-run the same read-only check to establish the remediation regression test.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not established.
- **Unconfirmed:** the signal is ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record the attempts; do not claim every theoretical variant was exhausted.
- Status, banners, stack traces, response length, endpoint existence, tool alerts, or frontend state are not sufficient on their own.

### Stop, cleanup, and handoff

Stop at scope boundaries, unexpected real-user data, production side effects, rate-limit/availability degradation, secret exposure, or prohibited action. Clean up disposable state, revoke temporary sessions/tokens when possible, and record status. Return target/scope evidence, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence, handoff signal, and cleanup status. Trigger a chained skill only when its signal is observed.

## References

- [uphiago/recon-skills — cloud posture related references](https://github.com/uphiago/recon-skills/tree/main)
- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Azure security best practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)
- [Google Cloud security foundations](https://cloud.google.com/architecture/security-foundations)


## Practical cloud validation: read-only first
Build the provider/resource ownership link from public metadata and the program's scope definition before active API calls. For cloud CLIs, verify the authenticated principal first and use read-only lookups only for explicitly authorized resources.

```bash
# These commands inspect the tester's configured identity; they do not establish target ownership.
aws sts get-caller-identity
az account show --output json
gcloud auth list --filter=status:ACTIVE --format='value(account)'
```

Run only the provider-specific query supported by the actual toolchain and approved asset list. Never infer permission from a public bucket/endpoint, a provider fingerprint, or a secret-like string. A reportable chain needs target ownership → reachable misconfiguration → protected resource/action actually exposed. Route confirmed storage/IAM/runtime findings to attack-minio-s3, aws-postexploit, azure-postexploit, gcp-postexploit, or k8s-assessment as applicable.


## Enrichment: evidence chain for a cloud finding
Separate four facts: the resource belongs to the authorized target, it is reachable, its access policy is weaker than intended, and a controlled test demonstrates the resulting exposure or action. A provider fingerprint, public DNS name, or secret-like string is only a lead. Prefer read-only configuration inspection and synthetic test objects; do not use found credentials or enumerate unrelated tenant resources. Chain a confirmed storage finding to the matching provider skill, an identity-policy weakness to IAM analysis, and a customer-facing exposure to triage/reporting.


## Targeted quality-loop enrichment (2026-10-19)

### Effective permission and resource proof
Start from the approved account/project/subscription and exact role; preserve read-only identity and policy outputs before interpreting a setting. For each public-storage or IAM lead, check effective access (resource policy plus identity/organization boundaries), object existence, intended public contract, and a benign canary where one is available. Do not enumerate or retrieve customer contents to prove access. A permissive configuration is not automatically exploitable if a higher-level control blocks it; an exposed empty resource may have no demonstrated data impact. Route workload URL fetches to SSRF and externally consumed credentials to secret-exposure triage without using them. Include a minimally sufficient remediation and a regression check for the exact policy edge.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Authorized provider CLIs/consoles in read-only mode first (AWS CLI, Azure CLI, gcloud, kubectl, Terraform plan, or a relevant configuration scanner). Confirm account/project/context before reading.
- Treat CLIs as optional until locally verified; prefer read-only checks. State-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — web-facing controls.
- [MITRE ATT&CK](https://attack.mitre.org/) — threat context.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json
Checks metadata only; manually inspect the artifact and redaction.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare a known-good baseline with a control, vary one meaningful property, and record alternative explanations before calling a lead confirmed.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use the provider's read-only CLI/console for the specific cloud resource; Prowler or ScoutSuite can add posture coverage; Checkov is appropriate when IaC is available. Do not install all scanners if one direct policy query will answer the question.

### Installation and setup
- [Prowler](https://docs.prowler.com/) — official installation and cloud support matrix.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — source and setup.
- [Checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html) — IaC scanning.
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli), or [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) depending on the provider.
Verify account/project/tenant and use read-only credentials. No tool install or cloud access authorizes modification/remediation.

### Primary resources
- [AWS Security](https://docs.aws.amazon.com/security/) — AWS.
- [Azure security](https://learn.microsoft.com/en-us/azure/security/) — Azure.
- [Google Cloud security](https://cloud.google.com/security) — GCP.
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — baseline controls.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json to track sanitized cloud evidence metadata.

### Result handling
Record provider/account context, resource/control, effective permission, observed exposure, and remediation state. Never put credentials or unrelated cloud inventory in shared notes.
