import { expect, test } from "bun:test"
import { assertTaskResumeScope, isInternalImpactHandoff } from "../../src/tool/task-resume"

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
