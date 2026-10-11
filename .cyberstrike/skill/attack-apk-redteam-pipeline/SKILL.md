---
name: attack-apk-redteam-pipeline
description: "Assess an authorized Android application package through static review and controlled runtime checks"
category: "mobile-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [android, apk, mobile, static-analysis, dynamic-analysis]
tech_stack: [android, apk, jadx, apktool, adb]
prerequisites:
  - "Written authorization for the application and any backend systems"
  - "Test APK, isolated emulator/device, and test account"
chains_with: [attack-idor-automation, attack-api-noauth, attack-oauth, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/apk-redteam-pipeline/SKILL.md"
---

# Android APK Assessment Pipeline

## When to use

Use for an authorized Android application review where the APK, its configuration, local storage, network traffic, or backend API interactions are in scope.

## Preconditions and safety

Use a test build or authorized APK and an isolated emulator/device. Do not extract or reuse real users' tokens, test third-party apps without permission, bypass paid services, or modify production accounts. Backend testing must independently be in scope.

## Procedure

1. **Record artifact provenance.** Capture APK source, version, package name, SHA-256, signing certificate metadata, and test environment.
2. **Perform static triage.** Inspect manifest permissions, exported components, deep links, network security configuration, cleartext settings, backup flags, embedded endpoints, and dependencies.
3. **Review code and resources.** Use static tools to locate authentication, authorization, storage, cryptography, WebView, intent, and API-handling code. Treat strings and decompiled output as leads.
4. **Set up isolated runtime.** Use an emulator/device configured for testing. Record OS version, app version, proxy setup, and any limitations.
5. **Observe network behavior.** Use only test credentials. Check TLS behavior, API routes, token storage, and sensitive data handling; redact all credentials and personal data.
6. **Review local storage.** Create synthetic test data and inspect app-private storage, logs, backups, screenshots, and clipboard behavior within the authorized environment.
7. **Check platform boundaries.** Review exported activities/services/receivers/providers, intent validation, deep-link routing, WebView bridges, and permission enforcement. Invoke only harmless test actions.
8. **Validate backend findings separately.** Route API authorization, OAuth, and session hypotheses to their dedicated skills; do not assume a mobile issue proves backend compromise.
9. **Document and clean up.** Save redacted evidence, remove test accounts/data where permitted, and preserve reproducible steps.

## Pitfalls

- Decompiled code can misrepresent runtime behavior.
- A hard-coded public endpoint or client identifier is not automatically a secret.
- Root detection, certificate pinning, or obfuscation is not itself a vulnerability.
- An exported component is not necessarily exploitable without a reachable security-sensitive behavior.

## Verification

Each finding should state the platform/API boundary, preconditions, static or runtime evidence, expected security control, demonstrated effect, device/app version, and confidence. Keep secrets and target-specific artifacts out of the repository.
