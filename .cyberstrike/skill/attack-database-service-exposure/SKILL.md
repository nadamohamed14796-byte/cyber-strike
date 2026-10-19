---
name: attack-database-service-exposure
description: "Assess externally reachable database and search services for unintended network exposure, authentication policy gaps, tenant/data boundaries, and unsafe operational endpoints."
category: "infrastructure-security"
version: "1.0.0"
tags: [database, redis, mongodb, postgresql, mysql, elasticsearch, opensearch, exposure]
tech_stack: [tcp, tls, redis, mongodb, postgresql, mysql, elasticsearch, opensearch]
prerequisites: ["Explicitly authorized host/service and allowed port range", "Prefer configuration review and read-only checks"]
chains_with: [recon-port-service-discovery, cloud-assessment, attack-nosqli, attack-information-disclosure, attack-triage-validation]
---

# Database and Search Service Exposure Review

## Objective
Determine whether a database/search service is reachable from an unintended network boundary and whether its effective access policy exposes a protected operation or data. A reachable port or product banner alone is not a confirmed vulnerability.

## Workflow
1. Establish asset ownership and allowed service-testing boundaries from the program rules. Keep provider/shared-host ambiguity as a passive lead.
2. Identify the service from approved inventory, configuration, TLS metadata, or a permitted low-impact handshake. Do not send writes, create accounts, change settings, or retrieve customer records.
3. Compare network reachability with intended architecture: private network, approved VPN, trusted application tier, allowlisted source ranges, or public endpoint by design.
4. Review authentication mode, TLS requirements, network ACL/firewall/security-group rules, default/anonymous access configuration, and administrative interface exposure from owner-provided config or read-only approved access.
5. If active validation is explicitly allowed, use only a provided test identity and synthetic database/index/collection. Verify one harmless metadata or synthetic-marker read, then a negative control with an unauthorized test identity.
6. Check whether network exposure is mitigated by strong authentication and least privilege; do not claim data exposure solely because the service accepts a TCP connection.
7. Record the minimum evidence needed and stop before enumeration, bulk queries, credential guessing, destructive commands, or configuration changes.

## Service-specific checklist

- **Redis:** network bind/protected-mode policy, ACL users, TLS, dangerous administrative commands, replication/configuration permissions, and whether the endpoint is intended to be private.
- **MongoDB:** authentication enabled, TLS, role separation, database/collection grants, and whether unauthenticated metadata differs from actual protected data access.
- **PostgreSQL/MySQL:** network exposure, TLS, authentication method, role grants, database/schema separation, and restricted administrative functions.
- **Elasticsearch/OpenSearch:** security plugin/authentication, index-level permissions, tenant/document controls, snapshot/management APIs, and separation between metrics and data endpoints.
- **Managed databases:** provider firewall/private endpoint configuration, public accessibility flag, approved source ranges, IAM/database-auth mapping, and resource-policy conditions.
- **Search/analytics consoles:** distinguish public dashboards from query APIs and admin controls; verify whether synthetic protected data is actually accessible.

## Evidence matrix

| Observation | What it proves | What it does not prove |
|---|---|---|
| Port accepts a TCP connection | A service is reachable from the tested vantage point | Anonymous data access or privilege |
| Product/version banner | A likely service family/version signal | Vulnerability or unpatched status without corroboration |
| Authentication challenge | An authentication boundary is present | Correct authorization after login |
| Synthetic fixture readable by intended identity | Positive control works | Access for other identities |
| Synthetic fixture readable by unauthorized test identity | Specific policy boundary failure, if reproducible | Access to every database/index or all customer data |
| Configuration permits broad ingress | Configuration weakness candidate | Exploitability if a higher-level boundary blocks access |

## False positives
- The endpoint is an approved public service with strong authentication and least privilege.
- A gateway/proxy exposes a health or metrics endpoint but not the data plane.
- The banner is a shared provider edge or a honeypot.
- Anonymous metadata is intentionally public and contains no sensitive information.
- A cloud console reports public network accessibility but security-group/identity policy prevents the tested action.

## Evidence contract
Record asset/scope proof, vantage point, service/protocol, TLS result, auth mode, network policy source, tested identity, synthetic fixture, expected policy, observed operation, positive/negative controls, result state, timestamp, and cleanup. Redact usernames where necessary and never store passwords, tokens, or customer records.

## Remediation
Prefer private endpoints, narrow ingress allowlists, TLS, managed identity or strong authentication, least-privilege roles, separation of admin/data/metrics endpoints, audited access, and regression checks for the exact network and identity boundary.

## References
- https://owasp.org/www-project-web-security-testing-guide/
- https://www.cisecurity.org/cis-benchmarks
- https://redis.io/docs/latest/operate/oss_and_stack/management/security/
- https://www.mongodb.com/docs/manual/security/
- https://www.postgresql.org/docs/current/client-authentication.html
- https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html

## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts the agent can invoke directly; browser UI, extensions, and interactive intercepting proxies are not dependencies. Verify official install docs, version, license, platform compatibility, and operational impact before use.

### Recommended tools
- nmap service detection with narrow approved ports
- nrich/fingerprintx where supported for service metadata
- Native database clients only for unauthenticated handshake or explicitly provisioned test accounts
- Python/jq for inventory parsing

### Resources
- https://nmap.org/book/man.html
- https://github.com/projectdiscovery/fingerprintx
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids, not a substitute for reviewing source, release provenance, and supported behavior.

### Helper-script contract
Record protocol handshake, auth-required state, TLS, source IP context, and intended exposure. Do not attempt credential guessing or enumerate database contents; a reachable port/banner alone is not a finding.

Preserve native evidence; normalize to a separate file. Keep source, timestamp, tool/version, error state, confidence, and redaction. Use explicit paths, machine-readable output, and local test fixtures. Never silently treat missing data as a pass.

### Handoff
Return actual commands/tool versions, input/output paths, records checked, failures, confidence, limitations, and next skill. A detected service or misconfiguration is a lead until impact is confirmed.
