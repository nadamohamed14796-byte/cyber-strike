---
name: attack-race-condition
description: "Validate race conditions and TOCTOU flaws with bounded concurrent tests on test-owned records"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - race-condition
  - toctou
  - web
  - business-logic
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-362
  - CWE-367
chains_with: []
prerequisites: []
severity_boost: {}
---

# Race Condition / TOCTOU Attack

## Objective

Exploit time-of-check-to-time-of-use (TOCTOU) vulnerabilities by sending concurrent requests that bypass server-side validation.

## Testing Methodology

### Phase 1: Identify Targets

State-changing operations vulnerable to race conditions:
- Coupon/promo code redemption
- Fund transfers / payments
- Vote/like systems
- Account creation (duplicate)
- Inventory purchase
- Password/email change
- File operations

### Phase 2: Automated Race Testing

```bash
# Only against a test-owned disposable coupon/record, with explicit permission; start with five requests
attack_script race_tester "https://TARGET/api/redeem" \
  -m POST \
  -H "Authorization:Bearer TOKEN" \
  -d '{"coupon":"TEST_CANARY_COUPON"}' \
  -c 5 \
  --json-output

# With delay (staggered)
attack_script race_tester "https://TARGET/api/test-transfer" \
  -m POST \
  -H "Authorization:Bearer TEST_ACCOUNT_TOKEN" \
  -d '{"to":"TEST_OWNED_ACCOUNT_ID","amount":1}' \
  -c 5 \
  --delay 5
```

### Phase 3: Single-Packet Attack (Turbo Intruder)

For critical timing, send all requests in a single TCP packet:

```bash
# Use a test-owned disposable coupon and cap concurrency at five; never race production payments or other users' records
for i in $(seq 1 5); do
  curl --max-time 15 --connect-timeout 5 -s -X POST https://TARGET/api/test-redeem \
    -H "Authorization: Bearer TEST_ACCOUNT_TOKEN" \
    -d '{"coupon":"TEST_CANARY_COUPON"}' &
done
wait
```

### Phase 4: Analysis

Look for:
- Multiple successful responses (coupon applied 2+ times)
- Balance inconsistencies
- Duplicate records created
- Response length/status variations indicating multiple successes

### Phase 5: Limit Bypass Race

```bash
# If explicitly permitted, use a test account and a low-volume authentication test; never test real users or guess passwords
attack_script race_tester "https://TARGET/api/test-login" \
  -m POST \
  -d '{"email":"YOUR_TEST_ACCOUNT@example.invalid","password":"INVALID_TEST_VALUE"}' \
  -c 3

# Race on one-time action
attack_script race_tester "https://TARGET/api/claim-bonus" \
  -m POST \
  -H "Authorization:Bearer TOKEN" \
  -c 5
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Double-spend or duplicate transfer on a test transaction with demonstrated financial impact | Severity depends on the actual impact, exposure, and program policy; not automatically Critical |
| One-time test coupon reused beyond the allowed count | Severity depends on value, reachability, and impact |
| Rate limit bypass confirmed with a bounded test-account sequence | Severity depends on the protected action and practical abuse |
| Duplicate record creation | Medium (P3) |
| Vote/like manipulation | Low (P4) |

## Evidence Requirements

- Target endpoint and parameters
- Number of concurrent requests
- Multiple successful responses proving race succeeded
- Business impact (e.g., coupon applied twice, balance doubled)
- Status code distribution from race test

## Tools

- `attack_script race_tester` — async concurrent request sender

## Verification and Safe-Testing Gate

- Use only test accounts and disposable records. Do not race real payments, production inventory, password resets, or destructive actions unless the program explicitly authorizes a controlled test.
- Establish a sequential baseline first, then compare a small number of concurrent requests. Keep concurrency low and stop immediately if the service degrades or unintended state changes occur.
- Confirm a race only when the final state violates an invariant (for example, a one-time action succeeds twice), not merely because requests overlap or return different status codes.
- Record request ordering, timestamps, correlation IDs, response bodies, and final test-record state. Repeat only enough to establish reproducibility.
- Check idempotency keys, transaction boundaries, locks, and retry behavior. A client retry or duplicate response is not proof of a server-side race.
## Concurrency Test Plan and Invariants

Before testing, write down the business invariant that must remain true (for example, a one-time action can succeed once, inventory cannot become negative, or a quota cannot be exceeded). Use a test account and reversible test objects only.

| Test | Baseline | Concurrent variant | Required proof |
|---|---|---|---|
| One-time action | submit once sequentially | two to five synchronized requests | duplicate success and violated invariant |
| Balance/quota | perform a small allowed operation | bounded concurrent operations | server-side state inconsistent with the invariant |
| Coupon/invitation | redeem once | repeat with a small concurrency window | duplicate redemption or duplicate privilege actually persisted |
| Idempotency | repeat same request sequentially | repeat same idempotency key concurrently | duplicate side effect despite contract |

Start with low concurrency, a short timeout, and a unique test object. Do not test payment capture, real inventory, or other irreversible operations unless explicitly approved. Stop immediately if unexpected side effects appear.

Capture request IDs, timestamps, status codes, and the final authoritative state. A burst of successful HTTP responses is not enough; show the violated invariant and distinguish application-level race conditions from retry behavior or eventual consistency.

## References

- [uphiago/recon-skills — redteam/hunt-race-condition](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-race-condition/SKILL.md) — merged source.
- [elementalsouls/Claude-BugHunter — skills/hunt-race-condition](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-race-condition/SKILL.md) — merged source.

- [PortSwigger: Race Conditions](https://portswigger.net/web-security/race-conditions)
- [James Kettle: Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)
