---
name: attack-vmware-vcenter
description: "Assess externally in-scope VMware vCenter, ESXi management, Workspace ONE, and Aria exposure through version verification, vendor advisory matching, and safe boundary checks."
category: "infrastructure"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - vmware
  - vcenter
  - esxi
  - workspace-one
  - aria
  - virtualization
  - cve
tech_stack:
  - vmware-vcenter
  - vsphere
  - esxi
  - workspace-one
  - aria
  - saml
  - dcerpc
cwe_ids:
  - CWE-306
  - CWE-918
  - CWE-94
  - CWE-787
chains_with:
  - attack-saml-sso
  - attack-rce
  - attack-oauth
  - attack-exchange-owa
prerequisites: []
severity_boost:
  attack-rce: "Management-plane CVE exposure becomes an execution finding only after version, configuration, reachability, and authorized lab proof confirm the exact vulnerable path."
---

# VMware Management Plane Exposure Assessment

## Objective

Assess in-scope externally reachable VMware management products and verify patch/advisory applicability without running exploit code, trying default credentials, or modifying virtualization infrastructure. Internal-only vCenter and ESXi assets are out of scope unless the engagement explicitly includes internal testing.

## Testing Methodology

### Phase 1: Apply the external-only boundary

Confirm the exact public hostname and written scope. If the product is reachable only through VPN/internal address space, stop external testing and document it for a separately authorized internal assessment. Do not scan adjacent networks or infer scope from a certificate or DNS name.

### Phase 2: Fingerprint the correct VMware product

Use a small set of documented read-only endpoints and TLS certificate metadata to distinguish vCenter, ESXi, Workspace ONE Access/Identity Manager, Aria Automation, Aria Operations, and Horizon. A shared VMware branding page or /ui path alone is not enough to identify a vulnerable product.

### Phase 3: Collect build/version evidence safely

Inspect official version/build endpoints, HTML metadata, product documentation, and response headers with bounded requests. Corroborate at least two signals where available; treat hidden or backported build information as uncertain.

### Phase 4: Match current vendor advisories

Check the exact product and branch against current Broadcom/VMware security advisories and CISA KEV where relevant. Record affected and fixed builds, authentication prerequisites, network reachability, and any feature/plugin/config dependency. Do not assume every listed CVE is pre-auth or internet-exploitable.

### Phase 5: Check management exposure without credentials

Determine whether login pages, SSO/SAML metadata, MOB/API documentation, or health endpoints are publicly accessible. Public metadata and a visible login form are not unauthorized access. Do not call privileged methods, enumerate VMs/hosts/datastores, retrieve VM files, or use credentials.

### Phase 6: Assess authentication and federation configuration by review

Review documented SSO issuer/audience, certificate, identity-provider, and access policy from public metadata or owner-provided configuration. Do not submit altered SAML assertions, default passwords, host-header auth bypass payloads, DCE/RPC exploit packets, or command-execution probes to production.

### Phase 7: Validate suspected CVEs in an isolated lab

If active exploitability is necessary, reproduce the same product build/configuration in a disposable isolated lab without sensitive data, external egress, or connected production infrastructure. Use vendor-provided detection/patch-validation methods first. Production exploit execution requires explicit separate written authorization and a defined rollback plan.

### Phase 8: Report exact affected asset and stop

State exposed service, verified build confidence, advisory, preconditions, and what was/was not tested. Stop on signs of service instability, unexpected management behavior, or uncertainty about external vs internal boundaries.

## What Constitutes a Finding

- **Candidate / lead:** VMware product fingerprint, publicly reachable management UI, SSO metadata, or a build potentially within a CVE range.
- **Confirmed exposure/configuration issue:** a non-public management endpoint or sensitive metadata is accessible contrary to policy, with minimal evidence.
- **Confirmed CVE applicability:** exact build/branch plus necessary component and configuration prerequisites match a current vendor advisory; exploitability may still remain unverified.
- **Confirmed execution/auth bypass:** only through an isolated/authorized test establishing the exact boundary failure; do not infer this from version or route existence alone.
- **Not a finding:** a public login page, SAML metadata by design, /sdk reachability, or version disclosure without a demonstrated policy issue.

## Evidence Requirements

- Exact public scoped hostname, port, path, timestamp, response headers, and TLS certificate metadata.
- Version/build signals and source URL/date for the vendor advisory and fixed build.
- Authentication, component/plugin, and configuration prerequisites; note unknowns explicitly.
- Sanitized minimal response; never include credentials, session tokens, VM listings, datastore files, guest contents, or secrets.
- Clearly label whether validation was passive/read-only, test-tenant, lab, or not tested.

## Tools

- **curl / OpenSSL s_client:** low-rate endpoint and TLS metadata checks.
- **Broadcom/VMware security advisories:** authoritative fixed-build and prerequisite guidance.
- **CISA KEV:** verify whether a CVE is known exploited, not whether this asset is vulnerable.
- **Version/build comparison:** match exact branch/build using vendor documentation rather than guessed numeric ordering.
- **Isolated vendor lab:** reproduce only where active validation is separately approved.

## VMware Product and Exposure Matrix

| Product/surface | Safe evidence | Do not infer |
|---|---|---|
| vCenter/vSphere UI | Product/build metadata and login response | Login page is not admin access |
| vCenter SDK/MOB/API | Route reachability, auth challenge, documented policy | Reachability does not mean anonymous VM/host access |
| ESXi management | Exact external address, supported build, advisory match | Do not conflate ESXi hypervisor with vCenter server |
| Workspace ONE / Identity Manager | Product-specific version and advisory prerequisites | Do not execute SSTI/command payloads or auth-bypass probes on production |
| Aria/vRealize | Component/version/feature checks | Product family has distinct CVEs; don't transfer one product's CVE to another |
| SSO/SAML metadata | Issuer, entity ID, certificates, ACS URL | Metadata publication alone is usually expected |
| CVE candidate | Product branch, exact build, plugin/feature, exposed path | A CVE table or endpoint status code alone is not proof |
| Internal-only asset | Scope decision | Not testable under external-only boundary without separate written scope |

**Mitigation:** restrict management interfaces to trusted admin networks, keep supported builds patched, disable unused plugins/services, enforce strong SSO/MFA, reduce public metadata where appropriate, and monitor privileged management access.

## Verification and False Positives

- Product names and URL paths overlap; classify the exact VMware family before mapping an advisory.
- Build disclosure may be stale, proxied, or backported; corroborate against owner configuration/vendor support.
- A historical CVE can require a specific plugin, authentication state, local foothold, or internal network position; do not call it a pre-auth internet RCE unless the advisory confirms that vector.
- Never try default credentials, spray SSO users, invoke exploit templates, upload files, run commands, modify VMs, access datastores, or pivot to internal-only systems by default.
- Keep active proof in an isolated lab unless a separate explicit production exploit authorization and rollback plan exist.

## References

- [uphiago/recon-skills — vmware-vcenter-attack](https://github.com/uphiago/recon-skills/tree/main/redteam/vmware-vcenter-attack)
- [Broadcom Security Advisories](https://support.broadcom.com/security-advisories)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [VMware vSphere Documentation](https://docs.vmware.com/en/VMware-vSphere/index.html)
