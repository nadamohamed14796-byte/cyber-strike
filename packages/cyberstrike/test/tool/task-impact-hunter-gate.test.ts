import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { Vulnerability } from "../../src/session/vulnerability"
import { TargetMemory } from "../../src/target"
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
        // Simulate an explicit @-invocation: no inherited agent identity, with
        // ordinary task permission bypass enabled. The Impact Hunter-specific
        // evidence gate must still run before creating a child session.
        const task = await TaskTool.init({} as any)
        const manualCtx = mockCtx(session.id)
        manualCtx.extra = { bypassAgentCheck: true }
        await expect(task.execute({
          description: "Impact Hunter",
          subagent_type: "impact-hunter",
          background: true,
          prompt: "Investigate this finding.\nhandoff_mode: proof_gap\nfinding_id: " + finding.id,
        } as any, manualCtx)).rejects.toThrow("not linked to an existing target workspace")
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
        const task = await TaskTool.init({} as any)
        const manualCtx = mockCtx(session.id)
        manualCtx.extra = { bypassAgentCheck: true }
        await expect(task.execute({
          description: "Impact Hunter",
          subagent_type: "impact-hunter",
          background: true,
          prompt: "Investigate this finding.\nhandoff_mode: approved_impact\nfinding_id: " + finding.id,
        } as any, manualCtx)).rejects.toThrow("latest validation does not contain ten complete evidence-backed checks")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})


test("manual Impact Hunter dispatch is blocked without the explicit vulnerability-testing checkpoint", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const target = "https://task-gate.example.test"
        await TargetMemory.configureScope(target, {
          include: ["task-gate.example.test"],
          authorizationSource: "Impact Hunter phase-gate fixture",
          authorizationReference: "https://task-gate.example.test/security",
        })
        const workspace = await TargetMemory.ensure(target)
        const request = Request.add({
          sessionID: session.id,
          method: "POST",
          normalizedPath: "/api/home",
          rawRequest: "POST /api/home HTTP/1.1\\r\\nHost: task-gate.example.test\\r\\n\\r\\n",
          scheme: "https",
          host: "task-gate.example.test",
          origin: target,
        })
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "medium",
            title: "Unconfirmed authorization bypass candidate",
            description: "A captured request is available but no reproducible bypass has been established.",
            endpoint: "POST https://task-gate.example.test/api/home",
            target_id: workspace.id,
          },
        })
        expect(request).toBeDefined()

        const task = await TaskTool.init({} as any)
        const manualCtx = mockCtx(session.id)
        manualCtx.extra = { bypassAgentCheck: true }
        await expect(task.execute({
          description: "Impact Hunter",
          subagent_type: "impact-hunter",
          background: true,
          request_id: request!.id,
          prompt: [
            "handoff_mode: proof_gap",
            "finding_id: " + finding.id,
            "target_id: " + workspace.id,
            "supporting_request_ids: " + request!.id,
          ].join("\\n"),
        } as any, manualCtx)).rejects.toThrow("explicit vulnerability_testing checkpoint is not active")
        expect(await Session.children(session.id)).toHaveLength(0)
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})
