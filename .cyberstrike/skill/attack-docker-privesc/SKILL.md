---
name: attack-docker-privesc
description: "Assess Docker container isolation and host-boundary exposure through read-only inspection of groups, sockets, capabilities, mounts, and daemon policy."
category: "infrastructure"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - docker
  - container
  - privilege-escalation
  - socket
  - linux
  - isolation
tech_stack:
  - docker
  - oci
  - linux
  - containerd
  - kubernetes
cwe_ids:
  - CWE-250
  - CWE-269
  - CWE-732
chains_with:
  - k8s-assessment
  - k8s-postexploit
  - attack-vmware-vcenter
  - attack-rce
prerequisites: []
severity_boost:
  attack-rce: "A container boundary weakness raises impact only when a controlled lab demonstrates host access; RCE inside a container is not automatically host compromise."
---

# Docker Container Boundary Assessment

## Objective

Determine whether a container's runtime configuration creates an excessive host trust boundary. Use read-only checks and source/config review; do not attempt a container escape or alter host files outside a disposable lab.

## Testing Methodology

### Phase 1: Confirm authorization and environment

Establish whether assessment is on a disposable container/lab or an approved production workload. For production, restrict this skill to read-only inventory and stop before creating containers, mounting host paths, or changing privileges.

### Phase 2: Inspect runtime identity and groups

Record current UID/GID, groups, capabilities from /proc/self/status, seccomp/AppArmor/SELinux hints, and no-new-privileges status. Do not use elevated commands or test setuid changes.

### Phase 3: Check Docker daemon socket exposure

Inspect whether the Docker socket path exists, its owner/group/mode, and whether it is documented as a required mount. Do not send API requests that create/delete containers or execute commands through the socket. Socket write access is a high-risk capability and should be reported from permissions/configuration alone unless a lab is available.

### Phase 4: Inspect mounts and host namespace exposure

Review /proc/self/mountinfo and namespace indicators for bind mounts of host-sensitive paths, host PID/network namespaces, privileged mode, and broad device/capability grants. Avoid reading mounted host secrets or accessing host files as proof.

### Phase 5: Review image, compose, and policy sources

Inspect Dockerfile, Compose/Kubernetes manifests, daemon configuration, image provenance, root user, package pinning, and secret mounts. Identify risky options such as privileged mode, hostPath, docker.sock, SYS_ADMIN, broad Linux capabilities, or writable host mounts.

### Phase 6: Validate in a disposable lab only

When authorized, reproduce the same manifest in an isolated test host with synthetic data and no production credentials or network access. Use the lab to confirm the impact of a documented misconfiguration, then reset the VM; do not use host-file writes, user creation, SSH-key insertion, SUID files, or persistence as production proof.

### Phase 7: Recommend and verify remediation

Remove unnecessary socket mounts/privileges, drop capabilities, apply user namespaces/rootless mode where feasible, restrict writable mounts, and rebuild from pinned trusted images. Confirm the configuration diff without making changes to the target.

## What Constitutes a Finding

- **Candidate / lead:** docker group membership, a daemon socket mount, privileged mode, host namespaces, SYS_ADMIN, or writable hostPath appears in configuration.
- **Confirmed misconfiguration:** a documented permission/configuration exceeds required workload needs and the affected trust boundary is clear.
- **Confirmed container escape:** lab-only execution proves host access on a disposable environment; do not claim host root from socket presence alone.
- **Not a finding:** containerized RCE without a demonstrated or configured host-boundary crossing, or a read-only socket that the runtime cannot write to.

## Evidence Requirements

- Environment, container identity, timestamp, runtime/engine version, sanitized effective configuration.
- Relevant group/capability/socket mode/mount options and source manifest line.
- Expected workload requirement versus granted privilege.
- Lab reproduction details and reset/cleanup confirmation if used; no host secrets or user data.

## Tools

- **id / /proc/self/status:** inspect identity and effective capability metadata.
- **findmnt / mountinfo:** review mount sources and flags without reading host data.
- **docker inspect / compose config:** use only read-only commands on an authorized environment.
- **Docker Bench / kube-bench / static manifest checks:** audit configuration without executing escape payloads.
- **Disposable VM/container lab:** test an approved proof-of-concept in isolation.

## Docker Host-Boundary Risk Matrix

| Control | Risk signal | Safe confirmation |
|---|---|---|
| Docker socket | Socket mounted and writable by workload identity | Inspect path ownership/mode/mount; no daemon API writes |
| docker group | Runtime user belongs to daemon-controlling group | Inspect group membership; don't run privileged containers |
| Privileged mode | Manifest grants privileged container | Review effective spec and owner need |
| Capabilities | SYS_ADMIN or other broad capabilities | Compare effective caps to minimum necessary |
| Host mounts | Writable mount of /, /etc, /root, /var/run, or device paths | Inspect mount metadata only; don't read/write host content |
| Host namespaces | hostPID/hostNetwork/hostIPC or shared namespace | Review config and required networking/process model |
| Root user | Container defaults to UID 0 | Assess whether rootless/userns or non-root user is feasible |
| Image provenance | Mutable tags, unpinned base images, embedded secrets | Verify digest/provenance and scan build context locally |

**Mitigation:** run non-root/rootless, remove docker.sock mounts, drop all unnecessary capabilities, disable privileged mode, restrict hostPath mounts, enforce seccomp/AppArmor/SELinux, pin trusted images, and isolate workload credentials.

## Verification and False Positives

- A mounted socket may be read-only or blocked by permissions; existence alone does not prove daemon control.
- Container root is not necessarily host root; namespaces, capabilities, LSMs, and runtime versions matter.
- Host mount paths in a manifest may not be active in the deployed container; compare effective runtime state.
- Stop before host file reads/writes, privileged container creation, chroot, host process inspection, credential access, or persistence. Use a disposable lab for escape validation only.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful, authorized read-only hypotheses. Continue while a distinct check can change the conclusion; deduplicate equivalent configuration checks and stop when evidence resolves the question, relevant branches are exhausted, prerequisites are unavailable, or scope/safety requires stopping. Do not perform host escape or modify production infrastructure.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

1. Confirm written authorization for the host/container and whether host-level validation is permitted; record container ID, image digest, namespace, and role without broadening to neighboring systems.
2. Use read-only inspection to inventory effective user, Linux capabilities, mounts, namespaces, privileged mode, exposed container-runtime sockets, and secret mounts.
3. Compare the observed configuration against the workload's intended requirement. A privileged setting is a risk indicator, but impact depends on effective isolation, mount permissions, and available host interfaces.
4. Demonstrate only the smallest capability in an isolated lab or approved disposable container. Do not attempt host escape, persistence, credential harvesting, or modification of production host files.
5. Provide a least-privilege remediation (drop capabilities, remove unnecessary mounts/socket access, run as non-root, enforce runtime policy) and a read-only regression check.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not established.
- **Unconfirmed:** the signal is ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record the attempts; do not claim every theoretical variant was exhausted.
- Status, banners, stack traces, response length, endpoint existence, tool alerts, or frontend state are not sufficient on their own.

### Stop, cleanup, and handoff

Stop at scope boundaries, unexpected real-user data, production side effects, rate-limit/availability degradation, secret exposure, or prohibited action. Clean up disposable state, revoke temporary sessions/tokens when possible, and record status. Return target/scope evidence, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence, handoff signal, and cleanup status. Trigger a chained skill only when its signal is observed.

## References

- [uphiago/recon-skills — docker-privesc](https://github.com/uphiago/recon-skills/tree/main/infra/docker-privesc)
- [Docker Engine security](https://docs.docker.com/engine/security/)
- [OWASP Kubernetes Top 10 / container security guidance](https://owasp.org/www-project-kubernetes-top-ten/)


## Targeted quality-loop enrichment (2026-10-19)

### Container-to-host boundary proof
Map runtime identity, group memberships, mounted sockets, host bind mounts, privileged flags, namespace settings, and capability grants from the approved test environment. Treat each as a distinct trust boundary; do not execute a host escape against a production workload. A mounted Docker socket or privileged flag is a strong configuration signal, but document the effective host authority reachable by the actual container identity using non-destructive read-only checks. Validate exploitability only in a disposable lab. Route image build-secret leakage to source/CI review and Kubernetes pod identity or RBAC gaps to the Kubernetes assessment skill.


## Read-only runtime snapshot

Run only inside an authorized container or on owner-provided configuration. These commands inspect metadata and do not attempt to use the Docker daemon or cross a host boundary.

```bash
id
grep -E '^(Uid|Gid|Groups|CapEff|NoNewPrivs|Seccomp):' /proc/self/status
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
test -S /var/run/docker.sock && stat -c '%A %U:%G %n' /var/run/docker.sock
```

If Docker CLI metadata inspection is authorized, inspect configuration only; do not invoke container creation, exec, copy, or privileged operations as part of this assessment. Redact mount source paths and environment values before storing evidence.

### Evidence record additions

Record runtime_version, container_image_digest, effective_uid_gid, groups, effective_capabilities, seccomp_status, lsm_status, socket_mode_owner, mount_sources_redacted, host_namespace_flags, workload_need, lab_validation_only, and cleanup_status. Separate configured risk from demonstrated host impact.


## Agent-executable CLI tooling, resources, and helper scripts

- `id` and `/proc/self/status`: inspect the current container identity/capability metadata in an authorized lab.
- `findmnt` and mountinfo: review mount sources/flags without reading host data.
- `docker inspect` / `docker compose config`: read-only configuration inspection in an authorized environment.
- Docker Bench, kube-bench, and static manifest checks: audit configuration without escape payloads.
- `python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json`: validate evidence metadata.

Verify each tool with its documented `--version` or `--help`. Official docs: https://docs.docker.com/, https://github.com/docker/docker-bench-security, https://github.com/aquasecurity/kube-bench. Use a disposable lab for any active reproduction; do not attempt host escape or modify production workloads.
