---
name: ad-security
description: Active Directory security testing and attack techniques
tags: [ad, windows, kerberos, ldap, internal-network]
chains_with: [attack-security-headers, recon-email-security, attack-triage-validation]
version: "1.0"
---

## Authorized assessment boundary
This skill covers enterprise Active Directory/internal identity controls and is not a default public-web bug-bounty workflow. Do not run credential dumping, password spraying, ticket attacks, DCSync, persistence, lateral movement, or evasion on a public target or an environment without explicit written authorization and a defined lab/engagement scope. For public programs, use passive asset/identity clues only when permitted and route findings to defensive configuration review. Use synthetic accounts, test domain controllers, narrow read-only checks, and documented cleanup in an isolated lab; never collect real employee credentials or secrets.


# Active Directory Security Testing

## Credential Access Techniques

| ID    | Technique              | Tool                     | Description                      |
| ----- | ---------------------- | ------------------------ | -------------------------------- |
| CA-01 | Kerberoasting          | GetUserSPNs.py, Rubeus   | Request TGS for service accounts |
| CA-02 | AS-REP Roasting        | GetNPUsers.py, Rubeus    | Attack accounts without preauth  |
| CA-03 | DCSync                 | secretsdump.py, Mimikatz | Replicate DC credentials         |
| CA-04 | LSASS Dump             | Mimikatz, ProcDump       | Extract credentials from memory  |
| CA-05 | SAM/SYSTEM Dump        | secretsdump.py           | Extract local credentials        |
| CA-06 | NTDS.dit Extraction    | secretsdump.py           | Offline DC credential dump       |
| CA-07 | Cached Credentials     | Mimikatz                 | Extract cached domain creds      |
| CA-08 | DPAPI Secrets          | Mimikatz, SharpDPAPI     | Decrypt protected data           |
| CA-09 | Credential Vault       | Mimikatz                 | Windows credential manager       |
| CA-10 | Browser Credentials    | SharpChromium            | Chrome/Edge saved passwords      |
| CA-11 | LLMNR/NBT-NS Poisoning | Responder                | Capture NTLMv2 hashes            |
| CA-12 | NTLM Relay             | ntlmrelayx.py            | Relay captured authentication    |
| CA-13 | Password Spraying      | Spray, Kerbrute          | Test common passwords            |
| CA-14 | GPP Passwords          | Get-GPPPassword          | Decrypt Group Policy preferences |

## Privilege Escalation Techniques

| ID    | Technique                             | Tool                  | Description                              |
| ----- | ------------------------------------- | --------------------- | ---------------------------------------- |
| PE-01 | ACL Abuse                             | BloodHound, PowerView | WriteDACL, GenericAll abuse              |
| PE-02 | GPO Abuse                             | SharpGPOAbuse         | Modify group policy                      |
| PE-03 | AD CS ESC1                            | Certipy               | Template allows user SAN                 |
| PE-04 | AD CS ESC2                            | Certipy               | Any purpose EKU                          |
| PE-05 | AD CS ESC3                            | Certipy               | Enrollment agent abuse                   |
| PE-06 | AD CS ESC4                            | Certipy               | Template ACL abuse                       |
| PE-07 | AD CS ESC5                            | Certipy               | PKI object access control                |
| PE-08 | AD CS ESC6                            | Certipy               | EDITF_ATTRIBUTESUBJECTALTNAME2           |
| PE-09 | AD CS ESC7                            | Certipy               | CA ACL abuse                             |
| PE-10 | AD CS ESC8                            | Certipy               | NTLM relay to HTTP enrollment            |
| PE-11 | Constrained Delegation                | Rubeus, getST.py      | S4U2Self/S4U2Proxy abuse                 |
| PE-12 | Resource-Based Constrained Delegation | Rubeus                | msDS-AllowedToActOnBehalfOfOtherIdentity |

## Lateral Movement Techniques

| ID    | Technique         | Tool                   | Description                     |
| ----- | ----------------- | ---------------------- | ------------------------------- |
| LM-01 | Pass-the-Hash     | Mimikatz, pth-winexe   | Authenticate with NTLM hash     |
| LM-02 | Pass-the-Ticket   | Rubeus, Mimikatz       | Inject Kerberos tickets         |
| LM-03 | Overpass-the-Hash | Rubeus                 | Request TGT with NTLM hash      |
| LM-04 | PSExec            | Impacket, Sysinternals | Remote execution via SMB        |
| LM-05 | WMI Execution     | wmiexec.py             | Execute commands via WMI        |
| LM-06 | DCOM Execution    | dcomexec.py            | Distributed COM abuse           |
| LM-07 | WinRM             | evil-winrm             | PowerShell remoting             |
| LM-08 | RDP Hijacking     | tscon.exe              | Take over disconnected sessions |
| LM-09 | SMB Relay         | ntlmrelayx.py          | Relay auth to other hosts       |
| LM-10 | SSH (Linux)       | ssh                    | Lateral to Linux systems        |

## Persistence Techniques

| ID    | Technique       | Tool                  | Description                    |
| ----- | --------------- | --------------------- | ------------------------------ |
| PS-01 | Golden Ticket   | Mimikatz, ticketer.py | Forge TGT with KRBTGT hash     |
| PS-02 | Silver Ticket   | Mimikatz, ticketer.py | Forge TGS for specific service |
| PS-03 | Diamond Ticket  | Rubeus                | Modify legitimate TGT          |
| PS-04 | Skeleton Key    | Mimikatz              | Master password on DC          |
| PS-05 | AdminSDHolder   | PowerView             | Persistent admin rights        |
| PS-06 | DCShadow        | Mimikatz              | Rogue domain controller        |
| PS-07 | SID History     | Mimikatz              | Add privileged SID to history  |
| PS-08 | Machine Account | Powermad              | Add computer to domain         |

## Enumeration Commands

### BloodHound Collection

```bash
# SharpHound (Windows)
SharpHound.exe -c All --zipfilename bloodhound.zip

# BloodHound.py (Linux)
bloodhound-python -d domain.local -u user -p pass -ns 10.0.0.1 -c all

# NetExec BloodHound
nxc ldap 10.0.0.1 -u user -p pass --bloodhound --collection All
```

### LDAP Enumeration

```bash
# Get domain info
ldapsearch -x -H ldap://10.0.0.1 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local"

# Find users with SPN (Kerberoastable)
ldapsearch -x -H ldap://10.0.0.1 -D "user@domain.local" -w 'pass' \
  -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName

# Find users without preauth (AS-REP Roastable)
ldapsearch -x -H ldap://10.0.0.1 -D "user@domain.local" -w 'pass' \
  -b "DC=domain,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
```

### NetExec Commands

```bash
# Enumerate users
nxc smb 10.0.0.1 -u user -p pass --users

# Enumerate groups
nxc smb 10.0.0.1 -u user -p pass --groups

# Find shares
nxc smb 10.0.0.1 -u user -p pass --shares

# Check for admin access
nxc smb 10.0.0.0/24 -u user -p pass

# Password spray
nxc smb 10.0.0.1 -u users.txt -p 'Spring2024!' --no-bruteforce
```

## Attack Paths

### Path 1: Domain User to Domain Admin

```
User Credential
    │
    ├─► Kerberoast SPN accounts
    │   └─► Crack service account password
    │       └─► Service account is Domain Admin
    │
    ├─► BloodHound Path Finding
    │   └─► ACL chain to DA group
    │       └─► WriteDACL → GenericAll → Add to DA
    │
    └─► AD CS Misconfiguration
        └─► ESC1: Request cert as DA
            └─► Authenticate as DA
```

### Path 2: Compromised Workstation to DC

```
Local Admin on Workstation
    │
    ├─► LSASS dump → cached domain creds
    │   └─► Domain user credential
    │       └─► Continue as Path 1
    │
    ├─► Find admin sessions
    │   └─► Lateral move to server
    │       └─► Dump DA credentials
    │
    └─► Unconstrained Delegation
        └─► Coerce DC authentication
            └─► Capture TGT → DCSync
```

## Important Impacket Tools

| Tool           | Purpose                         |
| -------------- | ------------------------------- |
| GetUserSPNs.py | Kerberoasting                   |
| GetNPUsers.py  | AS-REP Roasting                 |
| secretsdump.py | Dump secrets (DCSync, SAM, LSA) |
| smbexec.py     | SMB-based execution             |
| wmiexec.py     | WMI-based execution             |
| psexec.py      | PSExec-style execution          |
| ntlmrelayx.py  | NTLM relay attacks              |
| getST.py       | Request service tickets         |
| ticketer.py    | Create Golden/Silver tickets    |
| lookupsid.py   | SID enumeration                 |
| samrdump.py    | SAM Remote interface dump       |

## Authorization and Verification Gate

- Run Active Directory enumeration and attack-path tests only in an explicitly authorized domain/lab. Confirm the permitted hosts, accounts, time window, and whether credential-access or lateral-movement validation is allowed.
- Start with read-only enumeration and least-privileged test accounts. Treat a tool finding, SPN, ACL, delegation flag, or exposed share as a lead; verify the effective permission and practical impact before reporting.
- Do not dump hashes, extract credentials, alter group membership, create persistence, or move laterally on production systems unless the written engagement explicitly authorizes that action. Prefer lab fixtures and designated test accounts.
- For privilege escalation, prove the exact permission edge and the resulting access using a controlled account. Avoid modifying domain objects just to demonstrate a theoretical path.
- Keep captured directory data and credentials outside the reusable skill and report only redacted evidence. Do not include real usernames, hashes, tickets, or internal host inventories in committed files.

## Attack-Path Verification and Reporting

Model Active Directory findings as a chain of specific edges, not as a list of tool alerts. For every edge, record the principal, object, effective right, and resulting security boundary.

| Edge | Verify | Safe evidence |
|---|---|---|
| Principal to object | effective ACL, group membership, delegated right | read-only ACL output and controlled account context |
| Credential to service | whether a designated test identity can authenticate | approved test account; never reuse captured user credentials |
| Service to host | permitted access level and host scope | minimum access proof on an authorized lab endpoint |
| Host to domain privilege | exact group/ACL/delegation path | configuration evidence plus controlled non-destructive validation |
| Trust/delegation | actual impersonation or delegation boundary | test principals only; no access to unrelated mailboxes or files |

A SPN, unconstrained delegation flag, writable ACL, or graph path is not automatically exploitable. Confirm effective rights and practical impact while avoiding password spraying, credential dumping, persistence, and lateral movement unless each action is explicitly authorized.

Reports should include sanitized domain/host context, the exact relationship or permission, expected policy, observed access, impact, timestamps, and remediation. Keep tickets, hashes, passwords, and private directory exports out of committed evidence.

## Detection Evasion Considerations

| Action        | Detection             | Evasion                      |
| ------------- | --------------------- | ---------------------------- |
| Kerberoasting | 4769 events (RC4)     | Use AES encryption           |
| DCSync        | 4662 events           | Time-based, limit frequency  |
| Pass-the-Hash | 4624 Type 3 with NTLM | Overpass-the-Hash (Kerberos) |
| BloodHound    | LDAP queries          | Reduce collection scope      |
| Mimikatz      | AV signatures         | BOF, custom tools            |


## Chaining and impact enrichment
Treat email-authentication weaknesses as a signal, not standalone impact. Correlate SPF/DKIM/DMARC policy with the actual sending path, From-domain alignment, receiver disposition, and a controlled mailbox you own. Chain only when independently observed: spoofable domain use → receiver accepts a controlled test message → a credible impersonation path in the program's threat model. Do not claim account takeover from a missing DNS record alone. Link the result to `recon-email-security`, `attack-security-headers` where browser delivery context matters, and `attack-triage-validation`.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Use only the native audit/telemetry tooling of an explicitly authorized lab (for example, Event Viewer/PowerShell on Windows, journalctl/auditd on Linux, klist for Kerberos context, or provider logs where relevant). Check availability before commands; do not use internal post-exploitation techniques against public bug-bounty assets.
- Before treating an optional CLI command as runnable, verify its presence and version locally. Do not claim integrations or tools that the current runtime has not exposed.
- Start with passive/read-only observation. Only active tests against authorized assets; state-changing tests require an approved disposable fixture and explicit program permission.

### Primary resources
- [MITRE ATT&CK](https://attack.mitre.org/) — behavior taxonomy and detection context.
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) — authorized assessment and evidence handling.

### Small, reusable helper
    python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json
Keep an artifact manifest for read-only findings and configuration snapshots; do not store credentials or raw personal data in the manifest.

### Evidence and hand-off
- Save a sanitized artifact reference and the exact claim it supports. Keep credentials, full cookies, reset links, private user data, and raw secrets out of notes, global research storage, and commits.
- Mark the result confirmed, disproven, or still a hypothesis. If the key check cannot be run safely or the expected control is missing, record the gap rather than inventing a conclusion.

Lab boundary: this skill is for systems you own or an explicitly authorized isolated environment. Do not apply internal post-exploitation workflows to public bug-bounty assets. Record the lab, principal, starting state, and cleanup plan.
