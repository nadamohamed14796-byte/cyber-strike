import { describe, expect, test } from "bun:test"
import { HttpReplayRawTool, HttpReplayTool, shouldRejectUnauthorized, replayGovernorsFor } from "../../src/tool/http-replay"
import { Instance } from "../../src/project/instance"
import { Request } from "../../src/session/request"
import { Session } from "../../src/session"
import { TargetMemory } from "../../src/target"
import { Batch } from "../../src/replay/batch"
import { Send } from "../../src/replay/send"
import { tmpdir } from "../fixture/fixture"

test("structured and raw replay send nothing before explicit vulnerability-testing handoff", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      let requests = 0
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch() {
          requests++
          return new Response("should not be reached")
        },
      })
      const session = await Session.create({})
      try {
        const origin = server.url.origin
        const target = origin + "/probe"
        const port = Number(server.url.port)
        await TargetMemory.configureScope(origin, {
          include: [origin],
          authorizationSource: "HTTP replay checkpoint gate fixture",
          authorizationReference: "https://program.example.test/policy",
        })
        const captured = Request.add({
          id: "req_replay_gate_fixture",
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/probe",
          rawRequest: "GET /probe HTTP/1.1\\r\\nHost: 127.0.0.1:" + port + "\\r\\n\\r\\n",
          scheme: "http",
          host: "127.0.0.1",
          port,
          origin,
        })
        expect(captured).toBeTruthy()

        const ctx = {
          sessionID: session.id,
          messageID: "msg_replay_gate_fixture",
          agent: "cyberstrike",
          abort: new AbortController().signal,
          messages: [],
          metadata: () => undefined,
          ask: async () => {},
        } as never
        const structured = await (await HttpReplayTool.init()).execute({ request_id: captured!.id }, ctx)
        const raw = await (await HttpReplayRawTool.init()).execute({ request_id: captured!.id }, ctx)

        expect(structured.metadata.testingDenied).toBe(true)
        expect(structured.output).toContain("No replay request was sent.")
        expect(raw.metadata.testingDenied).toBe(true)
        expect(raw.output).toContain("No byte-exact request was sent.")
        expect(requests).toBe(0)
      } finally {
        await Session.remove(session.id)
        server.stop(true)
      }
    },
  })
})

describe("HTTP replay TLS verification", () => {
  test("rejects invalid certificates by default", () => {
    expect(shouldRejectUnauthorized(undefined)).toBe(true)
    expect(shouldRejectUnauthorized(false)).toBe(true)
  })

  test("accepts invalid certificates only with explicit opt-in", () => {
    expect(shouldRejectUnauthorized(true)).toBe(false)
  })
})

describe("HTTP replay governor lifetime", () => {
  test("shares the session budget and reuses host governors without crossing session or host boundaries", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const firstSession = await Session.create({})
        const secondSession = await Session.create({})
        try {
          const first = replayGovernorsFor(firstSession.id, "https://api.example.test")
          const repeated = replayGovernorsFor(firstSession.id, "https://api.example.test")
          const otherHost = replayGovernorsFor(firstSession.id, "https://www.example.test")
          const otherSession = replayGovernorsFor(secondSession.id, "https://api.example.test")

          expect(repeated.budget).toBe(first.budget)
          expect(repeated.breaker).toBe(first.breaker)
          expect(repeated.limiter).toBe(first.limiter)

          expect(otherHost.budget).toBe(first.budget)
          expect(otherHost.breaker).not.toBe(first.breaker)
          expect(otherHost.limiter).not.toBe(first.limiter)

          expect(first.budget.tryConsume()).toBe(true)
          expect(otherHost.budget.consumed).toBe(1)

          expect(otherSession.budget).not.toBe(first.budget)
          expect(otherSession.breaker).not.toBe(first.breaker)
          expect(otherSession.limiter).not.toBe(first.limiter)

          await Session.remove(firstSession.id)
          const afterDelete = replayGovernorsFor(firstSession.id, "https://api.example.test")
          expect(afterDelete.budget).not.toBe(first.budget)
          expect(afterDelete.breaker).not.toBe(first.breaker)
        } finally {
          await Session.remove(secondSession.id)
        }
      },
    })
  })

  test("Batch.run reads the shared AIMD limiter and Send.governed feeds it", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const session = await Session.create({})
        try {
          const governors = replayGovernorsFor(session.id, "https://api.example.test")
          let active = 0
          let maxActive = 0
          const results = await Batch.run(
            Array.from({ length: 16 }, (_, index) => index),
            async () => {
              active++
              maxActive = Math.max(maxActive, active)
              await new Promise<void>((resolve) => setTimeout(resolve, 2))
              const result = await Send.governed(
                async () => ({
                  response: {
                    version: "HTTP/1.1",
                    status: 200,
                    reason: "OK",
                    headers: [],
                    body: new Uint8Array(0),
                  },
                  timing: { totalMs: 1 },
                }),
                "GET",
                governors,
                { maxRetries: 0 },
              )
              active--
              return result.response?.status
            },
            { concurrency: () => governors.limiter.value },
          )

          expect(results.every((status) => status === 200)).toBe(true)
          expect(maxActive).toBeGreaterThan(1)
          expect(governors.limiter.value).toBeGreaterThan(2)
          expect(governors.budget.consumed).toBe(16)
        } finally {
          await Session.remove(session.id)
        }
      },
    })
  })
})
