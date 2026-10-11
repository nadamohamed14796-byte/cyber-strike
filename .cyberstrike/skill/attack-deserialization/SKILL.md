---
name: attack-deserialization
description: "Assess unsafe deserialization with non-destructive markers and evidence-led impact validation"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [deserialization, serialization, object-graph, validation]
tech_stack: [java, dotnet, php, python, nodejs, http]
prerequisites:
  - "Authorized endpoint and confirmation that testing this input format is allowed"
  - "A controlled test environment or harmless marker-based proof plan"
chains_with: [attack-api-misconfig, attack-sqli, attack-ssti, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-deserialization/SKILL.md"
---

# Unsafe Deserialization Assessment

## When to use

Use when an application accepts serialized objects, signed or unsigned state blobs, framework-specific object formats, or opaque values that appear to be decoded into complex server-side objects.

## Safety gate

Prefer a lab or staging environment. On production targets, use only non-destructive, program-permitted probes. Do not use payloads that execute commands, delete data, establish callbacks, or access secrets. Never assume a serialized-looking value is vulnerable.

## Procedure

1. **Identify the input.** Record parameter location, content type, encoding, size limits, and whether the value is client-controlled or integrity-protected.
2. **Establish a baseline.** Save the original request and response; change no more than one variable at a time.
3. **Identify format clues.** Look for documented framework formats, magic bytes, object type names, base64-wrapped data, or structured token fields. Treat signatures as clues, not proof.
4. **Test parser behavior safely.** Use malformed but small inputs and benign type/field markers where permitted. Observe validation errors, type errors, and whether the server accepts altered data.
5. **Check integrity protection.** Determine whether the object is signed, encrypted, bound to the user/session, or server-stored. Do not attempt key theft or cryptographic brute force.
6. **Look for a semantic sink.** A parser accepting input is not sufficient. Establish whether the decoded object influences authorization, file access, template rendering, job execution, or another security-relevant operation.
7. **Validate in an isolated environment.** If impact testing requires gadget chains or code execution, reproduce it in a lab or explicitly approved staging environment using benign proof-of-execution methods.
8. **Record boundaries.** Document required authentication, input control, integrity checks, reachable sink, and any mitigations.

## Pitfalls

- A stack trace or parser error alone does not prove unsafe deserialization.
- Signed serialization can still have object-level or authorization flaws, but those are separate hypotheses.
- A format name does not establish that dangerous types are instantiated.
- Do not run public exploit payloads against a production system as a first test.

## Verification

Require evidence of attacker-controlled object interpretation plus a meaningful security effect or a strong isolated reproduction. State clearly whether the result is confirmed, likely, or only a lead.
