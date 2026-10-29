import { expect, test } from "bun:test"
import { assertTaskResumeScope, isInternalImpactHandoff, selectTaskRequestContext } from "../../src/tool/task-resume"

test("resumes only a subtask owned by the current parent session", () => {
  expect(() => assertTaskResumeScope({ id: "child-1", parentID: "parent-1" }, "parent-1")).not.toThrow()
  expect(() => assertTaskResumeScope({ id: "child-1", parentID: "other-parent" }, "parent-1")).toThrow(
    "Cannot resume task child-1: it does not belong to the current parent session.",
  )
  expect(() => assertTaskResumeScope({ id: "root-session", parentID: null }, "parent-1")).toThrow()
})

test("only non-Impact-Hunter subagents can use the background handoff bypass", () => {
  const base = {
    subagentType: "impact-hunter",
    background: true,
    caller: "proxy-tester-xss",
    callerMode: "subagent" as const,
  }
  expect(isInternalImpactHandoff(base)).toBe(true)
  expect(isInternalImpactHandoff({ ...base, background: false })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, subagentType: "proxy-tester-idor" })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, caller: "impact-hunter" })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, caller: "cyberstrike", callerMode: "primary" })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, caller: undefined })).toBe(false)
})


test("an explicit request ID never falls back to a different request", () => {
  const requests = [
    { id: "req-old", status: "processed", time: { updated: 10 } },
    { id: "req-active", status: "processing", time: { updated: 20 } },
  ]
  expect(selectTaskRequestContext(requests, "req-old").request?.id).toBe("req-old")
  expect(selectTaskRequestContext(requests, "req-missing")).toEqual({ reason: "request_not_found" })
})

test("implicit request context is inferred only when unambiguous", () => {
  const requests = [
    { id: "req-finished", status: "processed", time: { updated: 30 } },
    { id: "req-active", status: "processing", time: { updated: 20 } },
  ]
  expect(selectTaskRequestContext(requests).request?.id).toBe("req-active")
  expect(selectTaskRequestContext([
    ...requests,
    { id: "req-active-2", status: "processing", time: { updated: 40 } },
  ])).toEqual({ reason: "ambiguous_processing_requests" })
})
