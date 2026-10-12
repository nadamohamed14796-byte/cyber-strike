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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis up to a maximum of 20; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Cosmetic variants of the same request do not count as independent attempts.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

Select distinct, low-impact hypotheses from this skill's coverage matrix; avoid repeating equivalent probes.

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
