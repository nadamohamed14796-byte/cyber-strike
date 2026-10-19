---
name: attack-xxe
description: "Assess XML parser external-entity handling with harmless local markers and approved callbacks"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [xxe, xml, parser, entity-resolution, ssrf]
tech_stack: [xml, http, api, java, php, dotnet]
cwe_ids: [CWE-611]
chains_with: [attack-ssrf, attack-triage-validation]
prerequisites:
  - "Authorized XML-consuming endpoint and approved test scope"
  - "A non-sensitive marker or program-approved callback service"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xxe/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# XML External Entity (XXE) Assessment

## Objective

Determine whether an XML parser processes attacker-controlled external entities or unsafe document types, potentially causing unauthorized file access, server-side requests, or denial of service. Use non-destructive validation only.

## Safety gates

Prefer a lab or staging environment. Do not read operating-system files, cloud metadata, internal services, or secrets from production. Do not use recursive entity expansion, oversized documents, or payloads designed to exhaust memory/CPU. Out-of-band testing must use an approved callback and unique non-sensitive marker.

## Procedure

### 1. Identify XML parsing surfaces

Review XML uploads, SOAP endpoints, SAML/XML integrations, document conversion, SVG processing, feed import, and API content types. Confirm the server actually parses XML rather than treating it as opaque text.

### 2. Establish baseline

Send a valid minimal XML document with a harmless marker. Record response behavior, parser errors, content type, and whether processing is synchronous or asynchronous.

### 3. Test DOCTYPE and entity behavior safely

In an authorized test environment, use a benign internal entity that expands to a fixed text marker. Check whether DTD processing is enabled and whether the marker appears in a predictable output. Avoid external file entities and recursive expansion on production.

### 4. Check external resolution only when permitted

If the program explicitly allows OOB testing, reference a unique token on a controlled callback domain and observe whether the server resolves or requests it. Do not send sensitive content to the callback or attempt to retrieve internal files. A callback proves external resolution, not necessarily file disclosure.

### 5. Separate impact classes

- Entity expansion visible in the response is in-band behavior.
- A controlled callback indicates out-of-band resolution.
- SSRF is a separate downstream impact and should be validated under `attack-ssrf` within the approved scope.
- File read or denial-of-service claims require separate, safe evidence and must not be tested destructively on production.

### 6. Remediation and cleanup

Recommend disabling external general/parameter entities and DTD processing when not required, using secure parser defaults, patching parser libraries, and limiting document size/depth. Remove test files and callback records if permitted.

## Common false positives

- The application echoes the XML without parsing it.
- A parser error mentions DTDs but no entity is resolved.
- The callback comes from a scanner or browser rather than the target server.
- The service normalizes XML or disables external resolution.
- A suspected file-read payload was never safely validated.

## Output contract

Return `xml_surface`, `parser_evidence`, `doctype_behavior`, `external_resolution`, `callback_evidence`, `impact_class`, `environment`, `cleanup_status`, `confidence`, and redacted evidence.


## Targeted quality-loop enrichment (2026-10-19)

### XML parser behavior and external resolution boundary
Identify accepted content types, parser configuration, DTD/entity behavior, and whether XML is handled by the application, gateway, or a downstream service. Establish a normal XML fixture and use a local lab callback or synthetic file controlled by the tester only when the program explicitly permits external-resolution testing. Do not attempt to read operating-system files, cloud metadata, internal endpoints, or environment secrets from production. A parser error that mentions DOCTYPE is not confirmation; verify whether external resolution occurred and what controlled result reached the response/log. Route non-XML serialized formats to deserialization review and outbound URL fetch behavior to SSRF only if a distinct source-to-request path is shown.
