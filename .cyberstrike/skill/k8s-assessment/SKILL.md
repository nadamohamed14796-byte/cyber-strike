---
name: k8s-assessment
description: READ-ONLY Kubernetes security assessment based on CIS Kubernetes Benchmark using kubectl
category: security-assessment
tags: [kubernetes, k8s, cis-benchmark, rbac, network-policy, pod-security, secrets, ingress, security-audit]
tech_stack: [kubernetes, kubectl]
cwe_ids: [CWE-269, CWE-284, CWE-311, CWE-732, CWE-693]
chains_with: [T1613, T1087.004, T1078.004]
prerequisites: []
version: "1.2.0"
---

# Kubernetes Security Assessment Methodology

READ-ONLY Kubernetes security assessment using kubectl CLI. No resources are created, modified, or deleted — all checks use get/list/describe/auth can-i verbs only. Based on CIS Kubernetes Benchmark v1.8+.

## Scope and Safety Preconditions

- Confirm the authorized cluster, context, namespaces, and allowed assessment window before running any checks. A kubeconfig entry alone does not establish authorization or scope.
- Capture `kubectl config current-context` and the active namespace before assessment. If the context or cluster identity is unexpected, stop rather than probing.
- Run `k8s_audit verify_readonly` first as described below. Also use `kubectl auth can-i` to check permissions; neither check replaces the written scope and least-privilege requirements.
- Keep the assessment read-only. Do not create pods, exec into workloads, change RBAC, fetch secret values, or test node/host access as part of this checklist.

## Prerequisites

1. **kubectl installed** — `kubectl version --client`
2. **kubeconfig with read access** — cluster-viewer or equivalent ClusterRole
3. **Verify read-only** — ALWAYS run `k8s_audit verify_readonly` first

```bash
# Quick prerequisite check
kubectl version --client     # verify kubectl
kubectl cluster-info         # verify cluster access
kubectl auth can-i list pods --all-namespaces  # verify read access
```

## Assessment Phases

### Phase 0 — Safety Check (MANDATORY FIRST STEP)

```
k8s_audit verify_readonly
```

Confirms current identity has no write/modify/delete permissions via kubectl auth can-i. If write permissions are detected, STOP and request a read-only kubeconfig.

### Phase 1 — RBAC Analysis

| Check | Command | CIS Benchmark |
|-------|---------|---------------|
| cluster-admin bindings | `k8s_audit rbac_audit` | 5.1.1 |
| Wildcard ClusterRoles | `k8s_audit rbac_audit` | 5.1.3 |
| Default SA permissions | `k8s_audit rbac_audit --namespace NS` | 5.1.5 |

### Phase 2 — Pod Security

| Check | Command | CIS Benchmark |
|-------|---------|---------------|
| Privileged containers | `k8s_audit pod_security_audit` | 5.2.1 |
| hostPID / hostNetwork | `k8s_audit pod_security_audit` | 5.2.2, 5.2.3 |
| Dangerous capabilities | `k8s_audit pod_security_audit` | 5.2.7-9 |
| Root execution | `k8s_audit pod_security_audit` | 5.2.6 |
| hostPath mounts | `k8s_audit pod_security_audit` | 5.2.13 |

### Phase 3 — Network Security

| Check | Command | CIS Benchmark |
|-------|---------|---------------|
| Missing NetworkPolicies | `k8s_audit network_policy_audit` | 5.3.2 |
| Default deny policies | `k8s_audit network_policy_audit` | 5.3.2 |
| Ingress TLS | `k8s_audit ingress_audit` | — |
| Ingress snippet injection | `k8s_audit ingress_audit` | — |

### Phase 4 — Secrets & Encryption

| Check | Command | CIS Benchmark |
|-------|---------|---------------|
| Secret types & counts | `k8s_audit secrets_audit` | 5.4.1 |
| Secrets as env vars | `k8s_audit secrets_audit` | 5.4.1 |
| etcd encryption | `k8s_audit secrets_audit` | 1.2.29-30 |

### Phase 5 — API Server & Infrastructure

| Check | Command | CIS Benchmark |
|-------|---------|---------------|
| Anonymous auth | `k8s_audit api_server_audit` | 1.2.1 |
| Insecure port | `k8s_audit api_server_audit` | 1.2.19 |
| Admission controllers | `k8s_audit api_server_audit` | 1.2.11-16 |
| Audit logging | `k8s_audit api_server_audit` | 1.2.17-18 |

### Phase 6 — Workload Hardening

| Check | Command | CIS Benchmark |
|-------|---------|---------------|
| Resource limits | `k8s_audit resource_limits_audit` | 5.4.1 |
| LimitRange/ResourceQuota | `k8s_audit resource_limits_audit` | — |
| Image tags | `k8s_audit image_audit` | — |
| Untrusted registries | `k8s_audit image_audit` | — |
| SA auto-mount tokens | `k8s_audit serviceaccount_audit` | 5.1.5-6 |

## Evidence and Severity Gate

- For each finding, record the cluster/context, namespace, Kubernetes version where available, identity/ServiceAccount, exact read-only command, expected permission, observed permission, and timestamp.
- Distinguish configuration hardening gaps from demonstrated exposure. A privileged Pod spec or wildcard role is a lead; verify whether a reachable identity can actually use the permission and what boundary it crosses.
- Do not include Secret values, bearer tokens, kubeconfigs, certificate private keys, or raw customer workloads in reports or repository examples. Use metadata or an approved synthetic resource for verification.
- Follow the engagement’s accepted-impact policy and severity rubric; do not assign severity from a CIS control failure alone.

## Verification and False Positives

- Keep checks read-only and verify the active kubeconfig context and namespace before every command. Do not create pods, change RBAC, read unrelated secrets, or modify workloads in this assessment.
- A role binding or pod security setting is a lead. Verify effective permissions with `kubectl auth can-i` and compare them with the intended role and namespace boundary.
- An exposed Secret object is not automatically a confirmed leak if the current identity cannot read its data. Do not print secret values; use metadata and an approved synthetic secret to prove access.
- Distinguish cluster-wide permissions from namespace-scoped permissions and document the actual service account or user identity used for the check.
- Preserve sanitized commands, context/namespace, role bindings, timestamps, and expected/observed results. Redact tokens, certificates, and private workload data.

## Scope and Validation Notes

- Verify the active kubeconfig context, cluster, and namespace allowlist before assessment; print and inspect the current context before issuing commands.
- Prefer read-only API queries and `kubectl auth can-i` to assess effective permissions. Do not create privileged pods, read unrelated secrets, or change RBAC in a read-only review.
- A privileged setting or missing policy is a lead, not automatically exploitable. Consider admission controls, runtime restrictions, namespace boundaries, and the actual service-account permissions.
- Use designated test namespaces and synthetic objects for any explicitly authorized active validation. Stop if workload health degrades or the test crosses the agreed namespace boundary.
- Record sanitized manifests, relevant RBAC output, context/namespace, timestamps, and the minimal evidence supporting impact. Redact tokens, secret values, and tenant data.

## Kubernetes Coverage and Evidence Matrix

Record the active context, cluster, namespace, identity, and authorization boundary before each test. Prefer read-only discovery and verify permissions with built-in authorization checks.

| Area | Review | Validation |
|---|---|---|
| RBAC | Role/ClusterRole bindings and subject scope | least-privileged test identity and effective can-i checks |
| Workloads | securityContext, capabilities, host mounts, service accounts | manifest review or test namespace |
| Secrets | mounts, env injection, API access | synthetic secret only |
| Network | NetworkPolicy and service exposure | bounded connectivity test between test pods |
| Admission | policy enforcement and exemptions | dry-run or designated test object |
| Tenant boundary | namespace/service-account separation | controlled test namespaces and synthetic resources |

Do not create privileged pods, mount host filesystems, read unrelated secrets, or change cluster-wide RBAC on production. A risky manifest alone is not proof; document the effective permission or reachable boundary, sanitized YAML, namespace/context, and safe remediation.

## Program Reference

| Program | Checks | CIS Section |
|---------|--------|-------------|
| verify_readonly | Write permission detection | — |
| rbac_audit | cluster-admin, wildcards, default SA | 5.1.x |
| network_policy_audit | Missing policies, default deny | 5.3.x |
| pod_security_audit | Privileged, hostPID, capabilities, root | 5.2.x |
| secrets_audit | Secret types, env exposure, etcd encryption | 1.2.29, 5.4.x |
| image_audit | Latest tags, pull policy, untrusted registries | — |
| api_server_audit | Anonymous auth, insecure port, admission, audit | 1.2.x |
| resource_limits_audit | CPU/memory limits, LimitRange, ResourceQuota | 5.4.x |
| ingress_audit | TLS, wildcard hosts, snippet injection | — |
| serviceaccount_audit | Auto-mount tokens, cluster-admin SAs, unused SAs | 5.1.x |


## Targeted quality-loop enrichment (2026-10-19)

### Kubernetes identity and workload boundary matrix
For each test cluster, record context/cluster identity, namespace, service account, RBAC verbs/resources, workload security context, mounted secrets, network policies, admission controls, and exposed control-plane routes. Use read-only effective-permission checks and synthetic namespace fixtures; do not list or export real secrets, exec into production workloads, create privileged pods, or alter cluster-wide resources without explicit authorization. A permissive RBAC rule is a posture issue until a controlled principal is shown to access a protected fixture. Route cloud workload identity to cloud assessment and container host-boundary configuration to Docker/container review. Include cleanup status and the precise resource/policy path in the evidence.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use kubectl for authorized read-only cluster context and configuration checks; Kubescape and kube-bench add Kubernetes security posture coverage; Trivy reviews images and dependencies. Choose based on whether the question is cluster, workload, or image-focused.

### Installation and setup
- [kubectl installation](https://kubernetes.io/docs/tasks/tools/) — official platform instructions.
- [Kubescape installation](https://kubescape.io/docs/getting-started/) — official setup.
- [kube-bench](https://github.com/aquasecurity/kube-bench) — official project/readme.
- [Trivy installation](https://trivy.dev/latest/docs/getting-started/installation/) — official release instructions.
Check kubeconfig context, namespace, and identity before running scans. Prefer a test cluster or read-only account; do not apply manifests or remediate settings without approval.

### Primary resources
- [Kubernetes security concepts](https://kubernetes.io/docs/concepts/security/) — workload and control plane model.
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — policy levels.
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — configuration baseline.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json to preserve a sanitized record of posture-check output.

### Result handling
Record cluster/context/version, namespace, control ID, observed state, exception/compensating control, and safe remediation guidance. Do not copy kubeconfigs or service-account tokens into the report.
