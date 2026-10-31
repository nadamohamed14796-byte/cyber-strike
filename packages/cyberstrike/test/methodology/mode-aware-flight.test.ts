import { expect, test } from "bun:test"
import { createModeAwareFlightRegistry } from "../../src/methodology/mode-aware-flight"

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((done, fail) => {
    resolve = done
    reject = fail
  })
  return { promise, resolve, reject }
}

test("same-key same-mode handoffs share one in-flight operation", async () => {
  const registry = createModeAwareFlightRegistry<string, "proof_gap" | "approved_impact", string>()
  const gate = deferred<string>()
  let calls = 0
  const run = () => {
    calls++
    return gate.promise
  }

  const first = registry("root:finding-1", "proof_gap", run)
  const duplicate = registry("root:finding-1", "proof_gap", run)

  expect(duplicate).toBe(first)
  expect(calls).toBe(1)
  gate.resolve("started")
  await expect(first).resolves.toBe("started")
})

test("mode transition waits for current handoff and keeps the newest mode deduplicated", async () => {
  const registry = createModeAwareFlightRegistry<string, "proof_gap" | "approved_impact", string>()
  const firstGate = deferred<string>()
  const secondGate = deferred<string>()
  const calls: string[] = []

  const proofGap = registry("root:finding-1", "proof_gap", () => {
    calls.push("proof_gap")
    return firstGate.promise
  })
  const approved = registry("root:finding-1", "approved_impact", () => {
    calls.push("approved_impact")
    return secondGate.promise
  })
  const duplicateApproved = registry("root:finding-1", "approved_impact", () => {
    calls.push("duplicate_approved_impact")
    return Promise.resolve("duplicate")
  })

  expect(duplicateApproved).toBe(approved)
  expect(calls).toEqual(["proof_gap"])

  firstGate.resolve("proof-gap-started")
  await expect(proofGap).resolves.toBe("proof-gap-started")
  await Promise.resolve()
  expect(calls).toEqual(["proof_gap", "approved_impact"])

  secondGate.resolve("approved-impact-resumed")
  await expect(approved).resolves.toBe("approved-impact-resumed")
})

test("a rejected current handoff does not strand the next mode transition", async () => {
  const registry = createModeAwareFlightRegistry<string, "proof_gap" | "approved_impact", string>()
  const firstGate = deferred<string>()
  const secondGate = deferred<string>()
  const first = registry("root:finding-2", "proof_gap", () => firstGate.promise)
  const second = registry("root:finding-2", "approved_impact", () => secondGate.promise)

  firstGate.reject(new Error("expected dispatch failure"))
  await expect(first).rejects.toThrow("expected dispatch failure")
  await Promise.resolve()
  secondGate.resolve("recovered")
  await expect(second).resolves.toBe("recovered")
})
