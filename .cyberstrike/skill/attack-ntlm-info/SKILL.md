---
name: attack-ntlm-info
description: "Collect and interpret NTLM challenge target-info metadata on explicitly scoped services without password guessing, relay, credential capture, or coercion."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - ntlm
  - smb
  - windows
  - active-directory
  - fingerprinting
tech_stack:
  - ntlm
  - http
  - smb
  - windows
  - active-directory
cwe_ids:
  - CWE-200
  - CWE-284
chains_with:
  - attack-exchange-owa
  - ad-security
  - kerberos-attacks
prerequisites: []
severity_boost: {}
---

# NTLM Challenge Metadata Assessment

## Objective

Determine whether an in-scope HTTP/SMB service exposes NTLM challenge metadata such as NetBIOS/DNS domain or host identifiers, and whether that disclosure is security-relevant under the engagement's policy. This skill does not cover password cracking, relay, coercion, or credential-theft operations.

## Testing Methodology

### Phase 1: Confirm scope and permitted authentication probe

Verify the exact service/hostname/port is in scope and that a single protocol handshake is permitted. Prefer a naturally occurring NTLM challenge from normal access. Don't scan the domain or enumerate unrelated services.

### Phase 2: Capture only a challenge response

Where permitted, request one unauthenticated resource that normally returns a Negotiate/NTLM challenge. Record WWW-Authenticate or protocol metadata. Do not supply usernames/passwords, repeat authentication attempts, or capture NTLM Type 3 responses.

### Phase 3: Decode metadata locally

Use a local parser to inspect the challenge target-info fields and record only relevant DNS/NetBIOS domain/host strings and flags. Do not upload captures to third-party decoders, publish raw challenge blobs, or attempt cracking/relay.

### Phase 4: Determine confidentiality and context

Compare the disclosed information to public DNS, certificates, and normal public service metadata. Domain/host disclosure may be intended for a public service and is not proof of credential compromise, relayability, or authentication bypass.

### Phase 5: Check configuration through approved evidence

If owner-provided config/source is available, review whether NTLM is required, whether modern authentication is expected, and whether challenge metadata is overexposed. Avoid triggering coercion or forcing outbound authentication to another service.

### Phase 6: Document the minimum result

Report only if disclosure exceeds expected policy or supports a separately confirmed issue. Include service, timestamp, sanitized metadata fields, and the reason they are considered non-public; never claim password access from a challenge alone.

## What Constitutes a Finding

- **Candidate / lead:** HTTP 401/Negotiate challenge or NTLM Type 2 metadata contains host/domain strings.
- **Confirmed metadata disclosure:** a specific non-public environment identifier is disclosed contrary to the program policy and its sensitivity is explained.
- **Not a finding:** NTLM challenge existence, a 401 response, normal domain metadata, or a claim that hashes/credentials can be cracked or relayed without separate authorized proof.

## Evidence Requirements

- Scoped host/port, route, timestamp, protocol, and response header.
- Sanitized target-info fields only; avoid raw auth blobs and all Type 3 responses.
- A comparison to expected/public metadata and the policy basis for sensitivity.
- No passwords, challenge-response hashes, session tokens, or unrelated domain inventory.

## Tools

- **curl / browser:** observe an expected challenge without supplying credentials.
- **Local NTLM parser:** parse challenge target-info offline.
- **Owner-provided config and Microsoft documentation:** determine whether legacy auth is needed.
- **Packet capture in a lab:** learn message types only with synthetic identities.

## NTLM Challenge Metadata Matrix

| Signal | What it can show | What it does not prove |
|---|---|---|
| WWW-Authenticate: NTLM/Negotiate | Service offers an integrated-auth mechanism | No credentials or bypass demonstrated |
| NetBIOS computer/domain name | Environment naming metadata | Not privileged access |
| DNS host/domain target-info | Host/domain identifiers | Not a reusable credential |
| 401 challenge | Authentication is expected | Not a vulnerability by itself |
| NTLM Type 3 material | Sensitive challenge-response data | Do not collect it in this workflow |
| Legacy auth enabled | Configuration posture | Exploitability depends on topology and policy |

**Mitigation:** disable legacy NTLM where feasible, prefer modern authentication, restrict service exposure, reduce unnecessary challenge disclosure, and monitor authentication configuration.

## Verification and False Positives

- Proxies can add or remove auth challenge headers; confirm which service responds.
- DNS and certificate data may already expose the same hostname information.
- NTLM Type 2 target-info is metadata, not a password or proof of relay.
- Do not perform password spraying, hash capture/cracking, relay, coercion, or outbound authentication tests as part of this skill.

## References

- [uphiago/recon-skills — exchange-owa-attack](https://github.com/uphiago/recon-skills/tree/main/recon/exchange-owa-attack)
- [Microsoft — NTLM Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [Microsoft — Restrict NTLM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852267(v=ws.11))
