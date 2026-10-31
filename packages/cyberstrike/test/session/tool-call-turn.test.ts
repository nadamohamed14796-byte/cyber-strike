import { describe, expect, test } from "bun:test"
import type { MessageV2 } from "../../src/session/message-v2"
import { hasToolCallForUserTurn } from "../../src/session/tool-call-turn"

function user(id: string): MessageV2.WithParts {
  return {
    info: { id, sessionID: "ses_test", role: "user", time: { created: 1 }, agent: "cyberstrike", model: { providerID: "test", modelID: "test" } },
    parts: [],
  } as unknown as MessageV2.WithParts
}

function assistant(
  parentID: string,
  finish: string | undefined,
  state: "pending" | "running" | "completed" | "error",
  error?: string,
): MessageV2.WithParts {
  const toolState = state === "pending"
    ? { status: state, input: {}, raw: "" }
    : state === "running"
      ? { status: state, input: {}, time: { start: 1 } }
      : state === "completed"
        ? { status: state, input: {}, output: "", title: "", metadata: {}, time: { start: 1, end: 2 } }
        : { status: state, input: {}, error: error ?? "provider tool failure", time: { start: 1, end: 2 } }
  return {
    info: {
      id: "msg_assistant",
      sessionID: "ses_test",
      role: "assistant",
      parentID,
      time: { created: 2 },
      modelID: "test",
      providerID: "test",
      mode: "test",
      agent: "cyberstrike",
      path: { cwd: "/", root: "/" },
      cost: 0,
      tokens: { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
      finish,
    },
    parts: [{
      id: "part_tool",
      sessionID: "ses_test",
      messageID: "msg_assistant",
      type: "tool",
      callID: "call_1",
      tool: "bash",
      state: toolState,
    }],
  } as unknown as MessageV2.WithParts
}

describe("tool-call gating per user turn", () => {
  test("does not count pending streamed tool input as an attempted call", () => {
    expect(hasToolCallForUserTurn([user("user_1"), assistant("user_1", undefined, "pending")], "user_1")).toBe(false)
  })

  test("counts tool-call finish even when the provider omits a tool part", () => {
    const callFinish = assistant("user_1", "tool-calls", "pending")
    callFinish.parts = []
    expect(hasToolCallForUserTurn([user("user_1"), callFinish], "user_1")).toBe(true)
  })

  test("counts running, completed and failed tool calls", () => {
    for (const state of ["running", "completed", "error"] as const) {
      expect(hasToolCallForUserTurn([user("user_1"), assistant("user_1", undefined, state)], "user_1")).toBe(true)
    }
  })

  test("does not let an earlier user turn satisfy the current turn", () => {
    const previous = assistant("user_old", "tool-calls", "completed")
    expect(hasToolCallForUserTurn([user("user_old"), previous, user("user_new")], "user_new")).toBe(false)
  })

  test("does not count pending input cleaned up after abort", () => {
    const aborted = assistant("user_1", undefined, "error", "Tool execution aborted")
    expect(hasToolCallForUserTurn([user("user_1"), aborted], "user_1")).toBe(false)
  })
})
