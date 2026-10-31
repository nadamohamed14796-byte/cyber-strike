import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Agent } from "../../src/agent/agent"
import { Vulnerability } from "../../src/session/vulnerability"
import { TaskTool } from "../../src/tool/task"

function mockCtx(sessionID: string): any {
  return {
    sessionID,
    messageID: "msg-impact-hunter-gate",
    agent: "cyberstrike",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => undefined,
  }
}

test("manual Impact Hunter task dispatch is blocked for an untriaged finding candidate", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "medium",
            title: "Unvalidated authorization lead",
            description: "The form action differs by role, but no server-side access bypass has been demonstrated.",
            endpoint: "POST https://task-gate.example.test/api/home",
          },
        })
        const caller = await Agent.get("cyberstrike")
        expect(caller).toBeDefined()
        const task = await TaskTool.init({ agent: caller })
        await expect(task.execute({
          description: "Impact Hunter",
          subagent_type: "impact-hunter",
          background: true,
          prompt: "Investigate this finding.\nfinding_id: " + finding.id,
        } as any, mockCtx(session.id))).rejects.toThrow("not explicitly triage-approved")
        expect(Vulnerability.get(session.id).find((row) => row.id === finding.id)?.status).toBe("new")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("manual Impact Hunter dispatch is blocked even when a finding is approved without its ten-check validation", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "medium",
            title: "Approved without validation fixture",
            description: "This fixture simulates a legacy or corrupted approval state.",
            endpoint: "POST https://task-gate.example.test/api/home",
          },
        })
        expect(Vulnerability.update({
          sessionID: session.id,
          id: finding.id,
          status: "approved",
          expectedStatus: "new",
        })).toBe(true)
        const caller = await Agent.get("cyberstrike")
        expect(caller).toBeDefined()
        const task = await TaskTool.init({ agent: caller })
        await expect(task.execute({
          description: "Impact Hunter",
          subagent_type: "impact-hunter",
          background: true,
          prompt: "Investigate this finding.\nfinding_id: " + finding.id,
        } as any, mockCtx(session.id))).rejects.toThrow("does not have a latest confirmed ten-check validation")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})
