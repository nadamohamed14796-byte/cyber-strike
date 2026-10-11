---
name: cloud-assessment
description: Multi-cloud READ-ONLY security assessment methodology for AWS, Azure, and GCP using CIS benchmark-aligned checks
category: assessment
tags: [cloud, aws, azure, gcp, security-audit, cis-benchmark, iam, storage, network, encryption, logging, dns, tls]
tech_stack: [aws, azure, gcp, aws-cli, az-cli, gcloud-cli]
cwe_ids: [CWE-269, CWE-311, CWE-319, CWE-693, CWE-778]
version: "1.2.0"
---

# Cloud Security Assessment Methodology

Multi-cloud READ-ONLY security assessment using the `cloud_audit` tool. All checks use describe/list/get CLI calls via native TypeScript — no Python dependency, no SDK imports. Uses aws/az/gcloud CLIs. Aligned with CIS benchmarks for AWS, Azure, and GCP.

## Safety First

**ALWAYS run `verify_readonly` before any other audit program.** This is a preflight check, not a mathematical guarantee that every write path is absent. If it returns FAIL, stop and request read-only credentials; if it passes, still confirm the active identity and scope and use only the documented read-only audit commands.

```
cloud_audit verify_readonly --provider all
```

## Assessment Phases

### Phase 1 — Credential Safety Verification

| Check | Command | Purpose |
|-------|---------|---------|
| Verify read-only | `cloud_audit verify_readonly --provider all` | Confirm no write permissions — MUST pass before proceeding |

### Phase 2 — Identity & Access Management

IAM is the most critical attack surface in cloud environments.

| Provider | Command | Key Checks |
|----------|---------|------------|
| AWS | `cloud_audit aws_iam_audit --json-output` | MFA status, wildcard policies, unused keys, cross-account trust, root access keys |
| Azure | `cloud_audit azure_iam_audit --json-output` | Dangerous role assignments (Owner/Contributor), subscription-level owners, wildcard custom roles |
| GCP | `cloud_audit gcp_iam_audit --json-output` | Primitive roles (Owner/Editor at project), SA key age >90d, domain-wide delegation |

**Intelligence integration:** After IAM audit, report findings via `add_intel` with type `infrastructure`:
```
add_intel type=infrastructure data="IAM audit: 3 users without MFA, 2 wildcard policies found"
```

### Phase 3 — Storage Security

Public storage buckets are the #1 cloud data breach vector.

| Provider | Command | Key Checks |
|----------|---------|------------|
| AWS | `cloud_audit aws_storage_audit --json-output` | S3 Block Public Access, ACLs, default encryption, versioning, access logging |
| Azure | `cloud_audit azure_storage_audit --json-output` | Blob public access, HTTPS-only, minimum TLS version, SAS policies |
| GCP | `cloud_audit gcp_storage_audit --json-output` | allUsers/allAuthenticatedUsers bindings, uniform bucket-level access, versioning |

### Phase 4 — Network Security

Open security groups and missing flow logs are common misconfigurations.

| Provider | Command | Key Checks |
|----------|---------|------------|
| AWS | `cloud_audit aws_network_audit --json-output` | SGs open to 0.0.0.0/0 on dangerous ports, IMDSv1, VPC flow logs |
| Azure | `cloud_audit azure_network_audit --json-output` | NSG Any/Any rules, public IPs on VMs, NSG flow logs |
| GCP | `cloud_audit gcp_network_audit --json-output` | Firewall rules open to 0.0.0.0/0, external IPs, legacy networks |

### Phase 5 — Encryption at Rest

Unencrypted storage is a compliance violation in most frameworks.

| Provider | Command | Key Checks |
|----------|---------|------------|
| AWS | `cloud_audit aws_encryption_audit --json-output` | EBS/RDS encryption, KMS key rotation, CMK vs AWS-managed |
| Azure | `cloud_audit azure_encryption_audit --json-output` | Disk encryption, storage CMK, Key Vault rotation |
| GCP | `cloud_audit gcp_encryption_audit --json-output` | Disk/SQL/GCS CMEK, KMS key rotation |

### Phase 6 — Logging & Monitoring

Missing audit logs mean attacks go undetected.

| Provider | Command | Key Checks |
|----------|---------|------------|
| AWS | `cloud_audit aws_logging_audit --json-output` | CloudTrail multi-region, GuardDuty, Config recorder |
| Azure | `cloud_audit azure_logging_audit --json-output` | Activity Log retention, Diagnostic settings, Defender status |
| GCP | `cloud_audit gcp_logging_audit --json-output` | Audit log config (DATA_READ/DATA_WRITE), log sinks, filters |

### Phase 7 — DNS & TLS

External-facing services need DNS security and valid TLS.

| Check | Command | Key Checks |
|-------|---------|------------|
| DNS | `cloud_audit dns_audit --domain TARGET` | Dangling CNAMEs (subdomain takeover), DNSSEC, CAA records |
| TLS | `cloud_audit tls_audit --target HOST:PORT` | Protocol version, certificate expiry, cipher strength, HSTS |

## Evidence and Severity Gate

- For each potential finding, capture provider, account/project/subscription, region, principal, resource, effective permission or configuration, and the exact read-only command used.
- Separate benchmark non-compliance from exploitable impact. A CIS failure can be a valid hardening gap without proving attacker reachability; label the finding accordingly and follow the program’s accepted-impact rules.
- Never place account IDs, tenant IDs, bucket names, hostnames, or principal names from a private environment into public examples. Sanitize evidence before storage or submission.
- Prefer least-privileged verification. Do not validate a public storage finding by downloading customer data; use metadata or an approved synthetic object and stop once the exposure is established.

## Vulnerability Reporting

For each FAIL finding, report via `report_vulnerability`:

```
report_vulnerability
  title: "AWS IAM user without MFA: admin-user"
  severity: high
  evidence:
    requestSent: "cloud_audit aws_iam_audit --json-output"
    responseCode: 0
    responseSummary: "checkId AWS-IAM-001 FAIL — user admin-user has console access without MFA"
    reasoning: "CIS AWS 1.10 requires MFA for all IAM users with console access"
```

## Coverage Notes

Use `record_coverage_note` with `scope: "wide"` for account-level findings:
```
record_coverage_note
  scope: wide
  note: "AWS IAM audit complete — 5 findings across 12 users. No root access keys detected."
```

## Verification and False Positives

- Keep the assessment read-only unless a specific state-changing test is explicitly authorized. Confirm the active account, tenant/project/subscription, and region before each provider-specific check.
- A public endpoint, broad-looking policy, or scanner warning is not by itself a confirmed finding. Verify effective access using the documented identity and a non-sensitive test resource.
- Separate configuration drift from exploitable impact. State which principal can perform which action on which resource, and what data or operation is actually exposed.
- Use provider-native audit evidence and least-privileged test identities. Do not retrieve real cloud credentials, export customer data, disable logging, or modify IAM policies as proof.
- Preserve sanitized commands, policy snippets, provider/account context, timestamps, and the relevant expected/observed behavior. Redact tokens, keys, and private resource identifiers.

## Scope and Validation Notes

- Record authorized account/tenant/project identifiers, regions, resource groups, and excluded services before running checks. Reachability does not establish authorization.
- Prefer read-only inventory and policy inspection. Validate effective access with a designated least-privileged test identity rather than inferring impact from a policy fragment alone.
- Use synthetic objects and designated test resources to demonstrate storage or identity exposure. Do not retrieve production secrets, modify IAM, disable logs, or create persistence as part of a read-only assessment.
- Treat benchmark deviations as configuration findings until exposure, exploitability, and business impact are established. Note compensating controls and exceptions to reduce false positives.
- Keep evidence minimal and sanitized: control ID, resource type, relevant setting, timestamp, and redacted command output. Never commit cloud credentials or customer data.

## Cloud Identity and Exposure Validation Matrix

Inventory the cloud provider, tenant/account/project, regions, identities, externally reachable services, data stores, and audit controls before testing. Keep a clear boundary between configuration review and active validation.

| Area | Review | Validate |
|---|---|---|
| Identity | role trust, privilege scope, stale credentials metadata | effective rights using a designated test identity |
| Network | public endpoints, firewall/security-group rules, private access | controlled connectivity check only |
| Storage/data | public access, cross-tenant policy, encryption and retention | synthetic test object; no real data export |
| Secrets | secret-management policy and access path | metadata/configuration proof; do not reveal secret values |
| Workloads | instance/container identity and patch posture | version/config evidence and approved test resource |
| Logging | audit coverage, retention, alerting | read-only policy and configuration evidence |

Report the exact resource scope, principal, effective permission or exposure, reproducible evidence, and remediation. Do not create credentials, weaken controls, disable logging, or modify production resources unless the rules of engagement explicitly permit the change.

## Program Reference

| Program | Domain | Providers |
|---------|--------|-----------|
| verify_readonly | Safety | AWS, Azure, GCP |
| aws_iam_audit | IAM | AWS |
| azure_iam_audit | IAM | Azure |
| gcp_iam_audit | IAM | GCP |
| aws_storage_audit | Storage | AWS |
| azure_storage_audit | Storage | Azure |
| gcp_storage_audit | Storage | GCP |
| aws_network_audit | Network | AWS |
| azure_network_audit | Network | Azure |
| gcp_network_audit | Network | GCP |
| aws_encryption_audit | Encryption | AWS |
| azure_encryption_audit | Encryption | Azure |
| gcp_encryption_audit | Encryption | GCP |
| aws_logging_audit | Logging | AWS |
| azure_logging_audit | Logging | Azure |
| gcp_logging_audit | Logging | GCP |
| dns_audit | DNS | Cross-cloud |
| tls_audit | TLS | Cross-cloud |
