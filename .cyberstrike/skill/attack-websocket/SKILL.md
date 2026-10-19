---
name: attack-websocket
description: "Assess WebSocket origin checks, authentication lifecycle, message authorization, and input handling"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [websocket, cswsh, origin, authorization, messages]
tech_stack: [http, websocket, browser, json]
cwe_ids: [CWE-346, CWE-284]
chains_with: [attack-idor-automation, attack-csrf, attack-triage-validation]
prerequisites:
  - "Authorized WebSocket endpoint and controlled account"
  - "Permission for message-level tests and low-volume connection checks"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-websocket/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# WebSocket Security Assessment

## Objective

Determine whether a WebSocket connection enforces expected origin, authentication, authorization, message validation, and session-lifecycle controls after the HTTP upgrade.

## Safety gates

Use only an in-scope endpoint and a controlled test account. Do not flood connections, send destructive messages, access other users' private channels, or replay another user's session. Keep message volume low and stop on service instability.

## Procedure

### 1. Discover and baseline

Identify the WebSocket URL, subprotocol, upgrade headers, authentication mechanism, origin behavior, and expected message schema from authorized application traffic or documentation. Record a normal connection and a harmless read-only message.

### 2. Test origin validation

Compare the legitimate application origin with a controlled untrusted origin. Where relevant, test absent or `null` origin behavior without involving real users. Origin rejection must be evaluated with cookie-based authentication context; a permissive origin alone is not enough to prove CSWSH.

### 3. Test authentication lifecycle

Compare controlled authenticated and unauthenticated connection attempts. Check whether expired/revoked sessions are rejected, whether logout invalidates an existing connection, and whether reauthentication is required after sensitive account changes. Never use another user's cookies or tokens.

### 4. Test message-level authorization

With two test accounts if permitted, compare access to a channel or object each account owns. Change one object/channel identifier at a time and verify semantic data access or state changes. Check authorization for every message/action, not only during the initial handshake.

### 5. Validate input and protocol handling

Use schema-valid harmless edge cases and small malformed messages to check server-side validation, type handling, and error behavior. Avoid oversized frames, rapid reconnect loops, or resource-exhaustion payloads. Record whether errors leak implementation details.

### 6. Assess CSWSH and cross-origin risk

If browser cookies authenticate the socket and untrusted origins are accepted, validate only with a local proof page and a controlled test account. Prove access to a harmless test-only message. Do not read another user's private messages or send a proof to real users.

### 7. Confirm impact and cleanup

Capture handshake metadata, origin, auth context, message schema, expected policy, and observed result. Close test connections and remove test data where permitted.

## Common false positives

- A WebSocket endpoint is publicly connectable but exposes only public data.
- Origin is permissive but authentication is token-based and not ambient.
- The handshake is authorized but each message is correctly checked.
- A malformed message returns an error without a security impact.
- A successful connection is misreported as authentication bypass.

## Output contract

Return `endpoint`, `origin_policy`, `auth_mechanism`, `session_lifecycle`, `message_action`, `object_boundary`, `observed_effect`, `cleanup_status`, `impact`, `confidence`, and redacted evidence.


## Targeted quality-loop enrichment (2026-10-19)

### Handshake vs message-level authorization
Record handshake origin, cookies/tokens, subprotocol, authenticated principal, session expiry/revocation, message schema, subscription topic, and server-side action separately. Establish a normal permitted message and a known-denied message with two tester-controlled accounts, then change one identity/topic/object dimension at a time. A successful 101 upgrade does not prove message authorization, and a rejected unknown opcode is not a finding. Use harmless read-only subscriptions or synthetic events; never trigger device controls or broadcasts visible to real users. Chain to CSWSH only when the browser automatically carries credentials and a controlled foreign origin can reach a protected action; chain to IDOR/BFLA for demonstrated message/object/function policy failures.


## Message catalog and lifecycle matrix

Keep a normalized message inventory keyed by direction + message type + field shape. Do not duplicate the endpoint for every message or object ID.

| Lifecycle stage | Controlled test | Evidence required |
|---|---|---|
| Handshake | Valid, absent, expired, and revoked test credential | Principal resolved by server and handshake decision |
| Origin | Legitimate origin vs controlled origin you own | Browser cookie context and whether a protected test message is available |
| Subscribe/join | Two test accounts subscribe to their own synthetic channels | Server enforces channel ownership at subscription time |
| Message/action | Same harmless message under allowed and denied test roles | Per-message authorization result and server-side state |
| Long-lived connection | Revoke test access, then send/read a harmless message on existing socket | Access is rechecked or remains valid contrary to documented policy |
| Reconnect | Reconnect with expired/revoked test session | New connection follows expected authentication policy |
| Event delivery | Emit synthetic event to test channel | Only authorized test principal receives the event |
| Input validation | Missing/wrong-type/unknown field in a harmless message | Safe rejection without unintended state change or sensitive error leakage |

### Evidence and note fields

Persist connection_id, origin, auth_source, principal, tenant, session_age, message_type, topic/channel, object_ref, schema_version, request_ref, expected_permission, actual_delivery_or_effect, negative_control, and cleanup_verified. Never persist full cookies, bearer tokens, or private message bodies.

### Chain rules

- Cross-origin browser can use ambient cookies and read a protected socket message → CSWSH candidate, with synthetic data only.
- A message names another object's ID but authorization is missing → BOLA/IDOR.
- A low role invokes an admin-only message action → BFLA.
- Message field changes a protected model property → property authorization/mass assignment.
- Only malformed frames or generic errors are observed → not a finding without a security boundary violation.
