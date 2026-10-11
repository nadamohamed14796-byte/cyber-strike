---
name: attack-k8s
description: "Review authorized Kubernetes workloads, RBAC, network boundaries, and secret handling"
category: "cloud-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [kubernetes, k8s, rbac, containers, cloud]
tech_stack: [kubernetes, kubectl, containers, cloud]
prerequisites:
  - "Explicit authorization for the cluster and namespace boundaries"
  - "Read-only kubeconfig or exported manifests where possible"
chains_with: [attack-cloud-iam, attack-cloud-misconfig, attack-cicd-security, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-k8s/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-k8s/SKILL.md"
---

# Kubernetes Security Assessment

## When to use

Use when assessing an authorized Kubernetes cluster, namespace, workload manifests, RBAC roles, service accounts, ingress, network policies, or secret-handling configuration.

## Safety gate

Confirm the cluster context and namespace before every operation. Prefer read-only commands and static manifest review. Do not create privileged pods, mount host filesystems, access secrets, or change production workloads without explicit written authorization.

## Procedure

1. Verify cluster identity, context, account, namespace, and engagement boundary.
2. Inventory workloads, service accounts, roles/bindings, ingress, network policies, and security contexts with read-only queries.
3. Review RBAC for wildcard verbs/resources, cluster-wide bindings, impersonation, secret access, and privilege-management permissions.
4. Inspect pod security settings: privileged mode, host namespaces, hostPath mounts, capabilities, runAs settings, read-only root filesystem, and resource limits.
5. Review service-account token automounting and whether workloads receive permissions they do not need.
6. Check network boundaries and ingress exposure against intended architecture; do not scan cluster-internal addresses outside scope.
7. Review image provenance, mutable tags, pull secrets, and deployment workflow trust.
8. Validate findings using exported manifests or policy tools before attempting any live action.
9. Recommend least privilege, namespace isolation, workload hardening, and secret rotation only where exposure is confirmed.

## Pitfalls

- A risky setting is not always exploitable without a reachable workload path.
- A role definition may be constrained by bindings and admission controls.
- Do not use production secret values as proof.
- Avoid live changes during assessment.

## Verification

Report cluster/namespace, resource kind/name, policy evidence, reachable boundary, impact, and remediation. Redact kubeconfig data, tokens, and internal identifiers.
