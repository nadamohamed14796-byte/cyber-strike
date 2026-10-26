---
name: attack-api-contract-testing
description: "Build a deduplicated API coverage map from permitted OpenAPI/Swagger or Postman contracts and compare declared security requirements with observed behavior."
category: "api-security"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [api, openapi, swagger, postman, contract-testing, endpoint-coverage, authorization]
tech_stack: [rest-api, openapi, postman, graphql, http]
cwe_ids: [CWE-285, CWE-862, CWE-863]
chains_with: [attack-api-noauth-hunt, attack-schema-enumeration, attack-shadow-api, attack-graphql, attack-triage-validation]
prerequisites:
  - "A confirmed in-scope API host and a contract, collection, or permitted documentation source"
severity_boost:
  high: "Observed behavior violates a documented authentication or authorization boundary and exposes a protected object or operation."
sources:
  - "https://github.com/usestrix/strix/blob/main/strix/skills/README.md"
  - "https://owasp.org/API-Security/"
---

# API Contract Testing

## Purpose

Use an available API contract to improve route coverage and compare the declared API with routes observed through JavaScript, crawling, documentation, and authorized traffic. The contract is an input to testing, not proof that a route is live or vulnerable.

## When to use it

Use this skill when a permitted OpenAPI/Swagger JSON or YAML document, a Postman collection export, or an explicitly supplied API contract is available. If there is no contract, continue the normal API/JavaScript workflow; do not block recon while searching indefinitely for one.

## Procedure

### 1. Load contract data safely

1. Prefer files already present in the target-local workspace, supplied exports, or links directly discovered from an in-scope page.
2. Parse OpenAPI/Swagger versions and Postman collection structures using an available safe parser. Do not execute collection pre-request/test scripts, import untrusted packages, or run generated client code.
3. Resolve local references normally. Fetch an external reference only if its host passes the same persisted scope check; never follow arbitrary `$ref` URLs or redirects to unapproved hosts.
4. Record the source, hash, version, collection/base URL, parse status, and any incomplete or unsupported sections. Malformed, partial, or truncated contracts remain incomplete.

### 2. Normalize operations

For each operation, capture origin/base URL, method, route template, operation ID/name, path/query/header/body parameters, content types, declared security requirements, response shapes, deprecated/version markers, and source location. Preserve multiple parameter observations on one endpoint record.

Use one canonical identity per origin + HTTP method + normalized route template. Merge contract, JavaScript, crawl, and captured-request evidence into the existing `endpoints.txt` inventory. Keep contract-only operations separate from observed-live operations in status/evidence fields; do not create a second endpoint row just because a spec and a crawler discovered the same endpoint.

### 3. Compare contract with observed surface

Classify each operation as contract-and-live, live-but-undocumented, contract-only/unverified, or unknown. Compare declared base paths and versions, methods, parameter types/requiredness, authentication declarations, and response content types against observed traffic. A mismatch is a hypothesis requiring validation; deployment differences, version drift, gateway behavior, and stale specs are alternative explanations.

Do not send requests to every route simply because it appears in a spec. Prioritize operations with object/tenant identifiers, admin roles, account changes, uploads/downloads, export/import, billing, auth recovery, or a mismatch supported by real traffic. Recheck scope for every host, redirect, and external service.

### 4. Validate security requirements minimally

1. Establish a baseline with a harmless in-scope operation and preserve its exact redacted request/response.
2. Read the operation-level security declaration and any inherited global requirement. Account for an operation intentionally setting an empty security list or representing a public endpoint.
3. Where authorized test identities exist, compare anonymous and low-privilege/test-owner behavior against the expected policy while changing one identity/role/object dimension at a time.
4. Prefer read-only operations and synthetic/test-owned objects. Do not invoke state-changing methods, destructive operations, payment workflows, messaging, or account changes without explicit authorization for that operation.
5. For object/field authorization, follow the evidence-matched path into `attack-api-noauth-hunt`, `attack-graphql`, or the existing IDOR/BOLA specialist. Keep required prerequisites, controls, and response evidence attached.

### 5. Evidence and verdicts

A route listed in a contract, public schema, deprecated endpoint, optional security scheme, 401/403/404 response, or undocumented operation is not by itself a vulnerability. Prove the relevant boundary failure and security impact under valid preconditions. A failed request does not disprove a hypothesis if identity, route/version, object validity, or other prerequisites are unknown.

For every plausible candidate, use the project's mandatory `validate_finding` ten-question evidence gate and durable verification ledger. Record missing evidence as unknown and leave unresolved cases inconclusive; do not label them false positive or confirmed based only on contract metadata.

## Output contract

Merge results into the canonical endpoint inventory and existing report/findings ledger. Retain contract source/hash, operation ID, declared security, observed-live status, method/route/parameters, auth context, evidence references, confidence, unresolved differences, and next safe test. Avoid a separate output file per source or a copy of every endpoint.

## Tool selection

Search the connected-tool registry and available local tools for an appropriate JSON/YAML/Postman parser or use a small, reviewed local parser if needed. Do not assume a particular CLI is installed. A missing parser must not block independent recon; mark unsupported portions explicitly and continue with sources that can be processed.
