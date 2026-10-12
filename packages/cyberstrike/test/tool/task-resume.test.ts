import { expect, test } from "bun:test"
import { assertTaskResumeScope } from "../../src/tool/task-resume"

test("resumes only a subtask owned by the current parent session", () => {
  expect(() => assertTaskResumeScope({ id: "child-1", parentID: "parent-1" }, "parent-1")).not.toThrow()
  expect(() => assertTaskResumeScope({ id: "child-1", parentID: "other-parent" }, "parent-1")).toThrow(
    "Cannot resume task child-1: it does not belong to the current parent session.",
  )
  expect(() => assertTaskResumeScope({ id: "root-session", parentID: null }, "parent-1")).toThrow()
})
