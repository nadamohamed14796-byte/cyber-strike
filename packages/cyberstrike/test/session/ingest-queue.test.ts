import { describe, expect, test } from "bun:test"
import { IngestQueue } from "../../src/session/ingest-queue"
import { IngestSummary } from "../../src/session/ingest-summary"
import { SessionQueueStatus } from "../../src/session/queue-status"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { Database, eq } from "../../src/storage/db"
import { RequestJavaScriptCaptureTable, RequestTable } from "../../src/session/session.sql"

function defer<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

async function withInstance(fn: () => Promise<void>) {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      await fn()
      await Instance.dispose()
    },
  })
}

describe("IngestQueue.enqueue", () => {
  test("runs a single task and updates pending count", async () => {
    await withInstance(async () => {
      const sid = "s1"
      const order: string[] = []
      IngestQueue.enqueue(sid, async () => {
        order.push("ran")
      })
      expect(IngestQueue.pendingCount(sid)).toBe(1)
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual(["ran"])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
      expect(IngestQueue.isPaused(sid)).toBe(false)
    })
  })

  test("runs tasks sequentially in enqueue order", async () => {
    await withInstance(async () => {
      const sid = "s2"
      const order: number[] = []
      const a = defer()
      const b = defer()
      IngestQueue.enqueue(sid, async () => {
        await a.promise
        order.push(1)
      })
      IngestQueue.enqueue(sid, async () => {
        await b.promise
        order.push(2)
      })
      expect(IngestQueue.pendingCount(sid)).toBe(2)
      b.resolve() // even if b ready first, must wait for a
      await new Promise((r) => setTimeout(r, 5))
      expect(order).toEqual([])
      a.resolve()
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual([1, 2])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
    })
  })

  test("task error does not break the chain or pending count", async () => {
    await withInstance(async () => {
      const sid = "s3"
      const order: string[] = []
      IngestQueue.enqueue(sid, async () => {
        throw new Error("boom")
      })
      IngestQueue.enqueue(sid, async () => {
        order.push("after-error")
      })
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual(["after-error"])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
    })
  })
})

describe("IngestQueue.pause / resume", () => {
  test("pause defers the next task until resume", async () => {
    await withInstance(async () => {
      const sid = "p1"
      const order: number[] = []
      const t1 = defer()
      const started = defer()
      IngestQueue.enqueue(sid, async () => {
        started.resolve()
        await t1.promise
        order.push(1)
      })
      // Wait until task 1 is actually in-flight before pausing
      await started.promise
      IngestQueue.pause(sid)
      IngestQueue.enqueue(sid, async () => {
        order.push(2)
      })
      // Finish task 1; task 2 should NOT run because we are paused
      t1.resolve()
      await new Promise((r) => setTimeout(r, 20))
      expect(order).toEqual([1])
      expect(IngestQueue.isPaused(sid)).toBe(true)
      expect(IngestQueue.pendingCount(sid)).toBe(1)

      // Resume → task 2 runs
      IngestQueue.resume(sid)
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual([1, 2])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
      expect(IngestQueue.isPaused(sid)).toBe(false)
    })
  })

  test("pause is idempotent", async () => {
    await withInstance(async () => {
      const sid = "p2"
      IngestQueue.pause(sid)
      IngestQueue.pause(sid)
      IngestQueue.pause(sid)
      expect(IngestQueue.isPaused(sid)).toBe(true)
    })
  })

  test("resume without pause is no-op", async () => {
    await withInstance(async () => {
      const sid = "p3"
      IngestQueue.resume(sid)
      expect(IngestQueue.isPaused(sid)).toBe(false)
    })
  })

  test("a pause racing with resume still blocks a queued task", async () => {
    await withInstance(async () => {
      const sid = "p5"
      const order: string[] = []
      IngestQueue.pause(sid)
      IngestQueue.enqueue(sid, async () => {
        order.push("ran")
      })

      // Let the queue enter waitIfPaused and create its first resume signal.
      await Promise.resolve()

      // Resolve that wait, then pause again before the continuation runs.
      // The queued task must observe the second pause rather than slipping through.
      IngestQueue.resume(sid)
      IngestQueue.pause(sid)
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual([])
      expect(IngestQueue.pendingCount(sid)).toBe(1)

      IngestQueue.resume(sid)
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual(["ran"])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
    })
  })

  test("enqueue while already paused waits at start", async () => {
    await withInstance(async () => {
      const sid = "p4"
      const order: string[] = []
      IngestQueue.pause(sid)
      IngestQueue.enqueue(sid, async () => {
        order.push("ran")
      })
      await new Promise((r) => setTimeout(r, 20))
      expect(order).toEqual([])
      expect(IngestQueue.pendingCount(sid)).toBe(1)
      IngestQueue.resume(sid)
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual(["ran"])
    })
  })
})

describe("IngestQueue parent-child controls", () => {
  test("parent pause gates child request queues without serializing siblings", async () => {
    await withInstance(async () => {
      const parent = "parent-ingest"
      const childA = "child-ingest-a"
      const childB = "child-ingest-b"
      const unrelated = "unrelated-ingest"
      const order: string[] = []

      IngestQueue.pause(parent)
      IngestQueue.enqueue(childA, async () => {
        order.push("child-a")
      }, parent)
      IngestQueue.enqueue(childB, async () => {
        order.push("child-b")
      }, parent)
      IngestQueue.enqueue(unrelated, async () => {
        order.push("unrelated")
      })

      await new Promise((r) => setTimeout(r, 20))
      expect(order).toEqual(["unrelated"])
      expect(IngestQueue.pendingCount(parent)).toBe(2)
      expect(IngestQueue.pendingCount(childA)).toBe(1)
      expect(IngestQueue.pendingCount(childB)).toBe(1)

      IngestQueue.resume(parent)
      await new Promise((r) => setTimeout(r, 20))
      expect(order).toContain("child-a")
      expect(order).toContain("child-b")
      expect(order).toHaveLength(3)
      expect(IngestQueue.pendingCount(parent)).toBe(0)
      expect(IngestQueue.pendingCount(childA)).toBe(0)
      expect(IngestQueue.pendingCount(childB)).toBe(0)
    })
  })
})

describe("IngestQueue isolation", () => {
  test("two sessions are independent", async () => {
    await withInstance(async () => {
      const sa = "iso-a"
      const sb = "iso-b"
      const order: string[] = []
      IngestQueue.pause(sa)
      IngestQueue.enqueue(sa, async () => {
        order.push("a")
      })
      IngestQueue.enqueue(sb, async () => {
        order.push("b")
      })
      await new Promise((r) => setTimeout(r, 20))
      // sb should run, sa should be paused
      expect(order).toEqual(["b"])
      expect(IngestQueue.isPaused(sa)).toBe(true)
      expect(IngestQueue.isPaused(sb)).toBe(false)
      IngestQueue.resume(sa)
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual(["b", "a"])
    })
  })
})

describe("SessionQueueStatus", () => {
  test("get returns default when nothing set", async () => {
    await withInstance(async () => {
      const got = SessionQueueStatus.get("none")
      expect(got).toEqual({ paused: false, pending: 0 })
    })
  })

  test("status reflects enqueue and drain", async () => {
    await withInstance(async () => {
      const sid = "qs1"
      IngestQueue.enqueue(sid, async () => {})
      // Right after enqueue, pending is 1
      expect(SessionQueueStatus.get(sid).pending).toBe(1)
      await new Promise((r) => setTimeout(r, 10))
      // Drained → defaults
      expect(SessionQueueStatus.get(sid)).toEqual({ paused: false, pending: 0 })
    })
  })

  test("status reflects pause", async () => {
    await withInstance(async () => {
      const sid = "qs2"
      IngestQueue.pause(sid)
      expect(SessionQueueStatus.get(sid).paused).toBe(true)
      IngestQueue.resume(sid)
      expect(SessionQueueStatus.get(sid).paused).toBe(false)
    })
  })
})


describe("Extension ingest transcript visibility", () => {
  test("writes intake and completion notices into the parent session transcript", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "extension-ingest-visibility-test" })
      await IngestSummary.notice(session.id, "Extension request queued for independent analysis: GET /profile")
      await IngestSummary.notice(session.id, "Extension request analysis completed: GET /profile")

      const messages = await Session.messages({ sessionID: session.id })
      const text = messages.flatMap((message) => message.parts)
        .filter((part) => part.type === "text")
        .map((part) => part.text)

      expect(text).toContain("Extension request queued for independent analysis: GET /profile")
      expect(text).toContain("Extension request analysis completed: GET /profile")
      await Session.remove(session.id)
    })
  })
})

describe("Request processing outcome persistence", () => {
  test("stores failed separately from processed", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "request-status-failure-test" })
      const request = Request.add({
        sessionID: session.id,
        method: "GET",
        normalizedPath: "/request-status-failure-test",
        origin: "https://example.test",
        keyHash: "request-status-failure-test-key",
      })
      expect(request).toBeDefined()
      if (!request) throw new Error("request fixture was not inserted")

      Request.updateStatus({ id: request.id, status: "processing" })
      expect(Request.get(session.id).find((item) => item.id === request.id)?.status).toBe("processing")

      Request.updateStatus({ id: request.id, status: "failed" })
      expect(Request.get(session.id).find((item) => item.id === request.id)?.status).toBe("failed")
      expect(Request.get(session.id).find((item) => item.id === request.id)?.status).not.toBe("processed")

      await Session.remove(session.id)
    })
  })
})


describe("full JavaScript source persistence", () => {
  test("stores complete .js response while keeping the normal request preview capped", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "javascript-source-persistence-test" })
      const source = 'fetch("/api/full-endpoint");\\n' + "x".repeat(110 * 1024)
      const request = Request.add({
        sessionID: session.id,
        method: "GET",
        normalizedPath: "/assets/application.js",
        origin: "https://example.test",
        keyHash: "javascript-source-persistence-test-key",
        response: {
          status: 200,
          headers: { "content-type": "text/plain" },
          body: source,
        },
      })
      expect(request).toBeDefined()
      if (!request) throw new Error("JavaScript request fixture was not inserted")
      expect(request.processed_response).toContain("[TRUNCATED - showing first 100KB")
      const stored = Database.use((db) =>
        db.select({ source: RequestTable.javascript_source })
          .from(RequestTable)
          .where(eq(RequestTable.id, request.id))
          .get(),
      )
      expect(stored?.source).toBe(source)
      await Session.remove(session.id)
    })
  })
})


test("retains changed JavaScript response versions when request analysis is deduplicated", async () => {
  await withInstance(async () => {
    const session = await Session.create({ title: "javascript-capture-history-test" })
    const common = {
      sessionID: session.id,
      method: "GET" as const,
      normalizedPath: "/assets/app.js",
      origin: "https://example.test",
      host: "example.test",
      scheme: "https" as const,
      keyHash: "javascript-capture-history-test-key",
    }
    const firstBody = 'fetch("/api/profile"); /* version one */'
    const secondBody = 'fetch("/api/profile"); fetch("/api/roles"); /* version two */'
    const first = Request.add({
      ...common,
      response: {
        status: 200,
        headers: { "content-type": "application/javascript" },
        body: firstBody,
      },
    })
    expect(first).toBeDefined()

    const second = Request.add({
      ...common,
      response: {
        status: 200,
        headers: { "content-type": "application/javascript" },
        body: secondBody,
      },
    })
    expect(second).toBeUndefined()

    const rows = Database.use((db) =>
      db.select()
        .from(RequestJavaScriptCaptureTable)
        .where(eq(RequestJavaScriptCaptureTable.session_id, session.id))
        .all(),
    )
    expect(rows).toHaveLength(2)
    expect(new Set(rows.map((row) => row.content_hash)).size).toBe(2)
    expect(rows.map((row) => row.source_url)).toEqual([
      "https://example.test/assets/app.js",
      "https://example.test/assets/app.js",
    ])
    expect(rows.map((row) => row.source_content).sort()).toEqual([firstBody, secondBody].sort())

    const repeatedBody = Request.add({
      ...common,
      response: {
        status: 200,
        headers: { "content-type": "application/javascript" },
        body: secondBody,
      },
    })
    expect(repeatedBody).toBeUndefined()
    const afterRepeat = Database.use((db) =>
      db.select({ id: RequestJavaScriptCaptureTable.id })
        .from(RequestJavaScriptCaptureTable)
        .where(eq(RequestJavaScriptCaptureTable.session_id, session.id))
        .all(),
    )
    expect(afterRepeat).toHaveLength(2)
    await Session.remove(session.id)
  })
})
