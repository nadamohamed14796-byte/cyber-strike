---
name: attack-race-condition
description: "Assess TOCTOU and concurrency defects with bounded tests on disposable, authorized state"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [race-condition, toctou, business-logic, concurrency, idempotency]
tech_stack: [http, api, web]
cwe_ids: [CWE-362, CWE-367]
chains_with: [attack-graphql, attack-idor-automation, attack-triage-validation]
prerequisites:
  - "Explicit permission for concurrency testing"
  - "Disposable test objects and documented rate/concurrency limits"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-race-condition/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Race Condition / TOCTOU Assessment

## Objective

Determine whether concurrent or reordered requests violate a server-side invariant because validation and state change are not atomic. A timing anomaly is not enough; the test must demonstrate an incorrect final state.

## Safety gates

- Use staging or a disposable test object/account. Never race real payments, refunds, inventory, account recovery, privilege changes, or actions affecting other users.
- Confirm the program permits concurrency testing and set an explicit low request limit.
- Do not run a stress test or attempt to degrade service. Stop on elevated latency, errors, or unexpected side effects.
- Do not rely on an unverified `attack_script` command; check the actual CLI help and tool registry first.

## Procedure

### 1. Identify invariants and candidate endpoints

Choose a state transition with a clear rule: one-time coupon redemption, quota, invitation acceptance, workflow approval, inventory reservation, or single-use token. Write down the expected result for sequential requests.

### 2. Establish sequential baseline

Using a disposable record, send the valid operation once and verify the persisted state. Repeat a second time sequentially to learn the expected duplicate/replay behavior. Record idempotency keys and server-generated identifiers.

### 3. Form a concurrency hypothesis

Identify whether the server checks eligibility, balance, ownership, token status, or quota before performing a separate update. Keep the hypothesis specific and test one invariant at a time.

### 4. Run bounded concurrent requests

Only if approved, use a small number of concurrent requests against the disposable state. Keep payloads identical unless testing a documented idempotency-key behavior. Avoid high concurrency, repeated loops, or financial/destructive actions on live production data.

### 5. Verify final state independently

Use a read-only endpoint or UI view to count resulting records, state transitions, redemptions, or quota usage. Compare against the expected invariant. A set of HTTP 200 responses does not prove the race succeeded; the final persisted state is the decisive evidence.

### 6. Repeat minimally and assess reproducibility

Repeat only enough to rule out a transient network issue. Record timing, request count, concurrency, idempotency headers, and state before/after. Stop once the violation is clear.

### 7. Cleanup

Restore disposable data or remove test artifacts through approved mechanisms. Do not reverse transactions or state changes that could affect real users without explicit authorization.

## Common false positives

- Client-side duplicate clicks while the server performs one transaction.
- Multiple successful HTTP responses but only one persisted state change.
- Eventual consistency that converges to the expected state.
- Retries caused by the client rather than concurrent server processing.
- Test instability due to network timing.

## Evidence and output

Return `invariant`, `sequential_baseline`, `concurrency_level`, `request_timing`, `final_persisted_state`, `reproducibility`, `cleanup_status`, `impact`, `confidence`, and redacted evidence.

## Related skills

- `attack-graphql` — compare concurrent GraphQL and REST mutations.
- `attack-idor-automation` — authorization boundaries on the same object.
- `attack-triage-validation` — validate impact and exclude timing false positives.


## Targeted quality-loop enrichment (2026-10-19)

### Concurrency proof without production stress
Write down the invariant, sequential baseline, expected final state, and exact controlled test object before scheduling any concurrent operation. Use the lowest concurrency needed to create overlap in a staging environment or disposable fixture; preserve request timestamps/correlation IDs and independently read back authoritative state. Network jitter, retries, idempotency behavior, and client double-clicks can mimic a race, so compare against sequential and single-request controls. Never race real purchases, transfers, refunds, seat/stock claims, or shared public benefits. Route the confirmed invariant violation to business-logic review and separately identify whether idempotency, locking, or atomic transition enforcement is the root cause.


## Minimal overlap harness for a disposable test fixture

Use this only against an explicitly approved staging endpoint with a disposable test object. Set the URL to a request you captured from the normal client; do not use a real payment, shared benefit, or destructive action. The default is two identical requests, no retry loop, and short timeouts.

```python
import concurrent.futures
import os
import time
import urllib.request

url = os.environ["AUTHORIZED_TEST_URL"]
token = os.environ["TEST_ACCOUNT_TOKEN"]
body = os.environ.get("TEST_REQUEST_BODY", "{}").encode()

def send_one(index):
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Test-Run": f"controlled-race-{int(time.time())}-{index}",
        },
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return {
                "index": index,
                "status": response.status,
                "elapsed_s": round(time.time() - started, 3),
            }
    except Exception as exc:
        return {
            "index": index,
            "error_type": type(exc).__name__,
            "elapsed_s": round(time.time() - started, 3),
        }

# Exactly two concurrent requests; verify the authoritative state separately afterward.
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    for result in pool.map(send_one, (1, 2)):
        print(result)
```

Do not print response bodies or tokens. Adapt the body to a test-owned fixture and the target's actual request schema. If the endpoint has external side effects, requires a one-time confirmation, or the program disallows concurrency, do not run this harness.

### Control matrix

| Run | Requests | Purpose |
|---|---:|---|
| Baseline | 1 | Establish normal transition and response |
| Sequential duplicate | 2 sequential | Establish idempotency/replay behavior |
| Overlap | 2 concurrent | Test whether validation/update is atomic |
| Read-back | 1 read-only query | Verify final persisted state and side effects |

Do not infer a race from two 2xx responses. A finding requires a final state that violates the written invariant, a sequential control, and a reproducible result. If a duplicate request is safely deduplicated, record the control as passing and move to another distinct invariant only if one is evidenced.

### Root-cause handoff

Record whether the likely root cause is check-then-act, missing uniqueness constraint, non-atomic balance/quota update, missing idempotency, stale cache/authorization, or asynchronous job duplication. Keep root-cause labels tentative unless code or approved telemetry confirms them. Chain to business-logic for the violated invariant and triage-validation for the evidence gate.
