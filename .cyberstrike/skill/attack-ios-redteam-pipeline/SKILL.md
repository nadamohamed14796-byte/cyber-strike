---
name: attack-ios-redteam-pipeline
description: "Assess an authorized iOS app through static review and controlled runtime testing"
category: "mobile-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [ios, mobile, ipa, keychain, deep-links]
tech_stack: [ios, swift, objective-c, xcode, proxy]
prerequisites:
  - "Written authorization for the app, device, and backend systems"
  - "Test build, isolated test device, and controlled account"
chains_with: [attack-apk-redteam-pipeline, attack-oauth, attack-api-noauth, attack-idor-automation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/ios-redteam-pipeline/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# iOS Application Assessment Pipeline

## When to use

Use when reviewing an authorized iOS application package, local data handling, URL schemes/universal links, network behavior, or API interactions.

## Safety gate

Use test accounts and a dedicated device or simulator. Do not extract real user data, reuse production tokens, bypass payment/licensing controls, or modify production accounts. Backend testing must be in scope separately.

## Procedure

1. Record app version/build, bundle identifier, signing metadata, device/iOS version, and artifact hash.
2. Review entitlements, URL schemes, universal links, ATS/network settings, permissions, background modes, and exported interaction surfaces.
3. Inspect binary/resources for API endpoints, hard-coded secrets, insecure cryptography, debug flags, and sensitive logging. A public client identifier is not automatically a secret.
4. Observe network requests using a controlled account; record TLS behavior, token storage, API authorization, and sensitive data handling.
5. Review Keychain usage, local files, caches, screenshots, clipboard, backups, and logs using synthetic data.
6. Check deep links and URL handling with harmless test inputs and ensure authorization is enforced after navigation.
7. Validate API issues with the relevant API skill and test identities; do not infer backend vulnerability from mobile code alone.
8. Clean up test records and redact credentials from evidence.

## Pitfalls

- Obfuscation or jailbreak detection is not itself a vulnerability.
- Static strings may be unused or non-sensitive.
- A deep link is not a bypass unless it crosses an enforced security boundary.

## Verification

State the app/build/device context, control expected, minimal runtime or static evidence, demonstrated impact, and limitations.
