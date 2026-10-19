---
name: attack-file-inclusion
description: "Assess path traversal, local file inclusion and unsafe file-selection boundaries using controlled canary files and non-sensitive proof."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags: [path-traversal, file-inclusion, lfi, rfi, file-download, normalization]
tech_stack: [HTTP, web, file-storage, PHP, Java, Node.js, Python]
cwe_ids: [CWE-22, CWE-23, CWE-36, CWE-98]
chains_with: [attack-source-leak, attack-information-disclosure, attack-file-upload, attack-triage-validation, attack-evidence-hygiene]
prerequisites:
  - "An in-scope file read/include/download feature"
  - "A benign tester-controlled canary file or isolated test fixture"
---
# File Inclusion and Path Traversal Assessment

## Objective
Determine whether a user-controlled path or file identifier can escape its intended directory, select an unauthorized file, or cause unsafe server-side inclusion. A path-shaped error is not proof; validate the canonicalized path boundary with a harmless canary under the permitted environment.

## Workflow
1. Identify the feature and expected root: download, image/document preview, template selection, import/export, language/theme file, or server-side include.
2. Capture a normal request for a tester-owned file and a negative control for a nonexistent in-root file. Record method, parameter location, content type, response fingerprint, and authorization context.
3. Review canonicalization and allowlisting: URL decoding, separator normalization, dot segments, symlinks, absolute paths, extension mapping, archive extraction, and platform-specific path handling.
4. In a lab or explicitly approved test fixture, place a harmless file with a unique marker at a known sibling path. Compare one traversal/normalization variant at a time and verify whether only that canary is returned.
5. Separate path traversal from file inclusion. A file being selected does not mean it is executed as code; execution must never be inferred from a parser error or response echo.
6. Stop if any response reveals real user data, operating-system secrets, credentials, or unexpected file content. Do not continue reading files to increase impact.

## Safe validation matrix
- Normal in-root canary path versus a known-invalid in-root path.
- Encoded/normalized separator and dot-segment variants in a disposable fixture.
- Filename-only selection versus a server-derived object ID.
- Download response versus preview/include/render path, only where the product exposes both.

Do not test access to system password files, environment dumps, cloud metadata, private application configs, or real customer files on public targets.

## What constitutes a finding
- **Candidate:** traversal-looking input, unusual error, or normalization difference.
- **Confirmed traversal:** a controlled canary outside the intended root is returned or processed by the server using an unauthorized path.
- **Confirmed inclusion/execution:** distinct evidence proves the selected file is interpreted in a server-side execution context in an authorized isolated environment.
- **False positive:** the server canonicalizes and constrains the path, returns a generic error, or only echoes the submitted filename.
- **Inconclusive:** no safe canary or permitted proof route exists.

## Chaining and impact
Use source-leak review for exposed build/source artifacts, file-upload review for untrusted stored files, and information-disclosure triage for a proven unauthorized read. Only chain to RCE when a separate execution primitive is safely demonstrated; never claim RCE from a traversal path alone.

## Evidence and remediation
Capture the sanitized request, canary marker, intended root, resolved path evidence where authorized, actual response behavior, authorization baseline, and cleanup proof. Recommend server-side allowlists/opaque file IDs, canonical path resolution under a fixed root, symlink-aware containment checks, isolated storage, and regression tests for encoded separators and traversal variants.

## References
- https://owasp.org/www-project-web-security-testing-guide/
- https://cwe.mitre.org/data/definitions/22.html
- https://portswigger.net/web-security/file-path-traversal
