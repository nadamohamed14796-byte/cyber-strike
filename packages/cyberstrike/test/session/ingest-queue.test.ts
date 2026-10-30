import { describe, expect, test } from "bun:test"
import { IngestQueue } from "../../src/session/ingest-queue"
import { IngestSummary } from "../../src/session/ingest-summary"
import { SessionQueueStatus } from "../../src/session/queue-status"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"
import { Session } from "../../src/session"
import { MessageV2 } from "../../src/session/message-v2"
import { Request } from "../../src/session/request"
import { TargetMemory } from "../../src/target"
import { Server } from "../../src/server/server"
import { Database, eq } from "../../src/storage/db"
import { RequestJavaScriptCaptureTable, RequestTable } from "../../src/session/session.sql"
import { Identifier } from "../../src/id/id"

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

  test("runs independent tasks concurrently for the same session", async () => {
    await withInstance(async () => {
      const sid = "s2"
      const releaseA = defer()
      const releaseB = defer()
      const started: string[] = []
      const finished: string[] = []
      IngestQueue.enqueue(sid, async () => {
        started.push("a")
        await releaseA.promise
        finished.push("a")
      }, undefined, true)
      IngestQueue.enqueue(sid, async () => {
        started.push("b")
        await releaseB.promise
        finished.push("b")
      }, undefined, true)
      expect(IngestQueue.pendingCount(sid)).toBe(2)
      await new Promise((r) => setTimeout(r, 10))
      expect(started.sort()).toEqual(["a", "b"])
      releaseB.resolve()
      releaseA.resolve()
      await new Promise((r) => setTimeout(r, 10))
      expect(finished.sort()).toEqual(["a", "b"])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
    })
  })


  test("keeps ordinary same-session tasks ordered by default", async () => {
    await withInstance(async () => {
      const sid = "serial-default"
      const releaseFirst = defer()
      const started: string[] = []
      const finished: string[] = []
      IngestQueue.enqueue(sid, async () => {
        started.push("first")
        await releaseFirst.promise
        finished.push("first")
      })
      IngestQueue.enqueue(sid, async () => {
        started.push("second")
        finished.push("second")
      })
      await new Promise((r) => setTimeout(r, 10))
      expect(started).toEqual(["first"])
      releaseFirst.resolve()
      await new Promise((r) => setTimeout(r, 15))
      expect(started).toEqual(["first", "second"])
      expect(finished).toEqual(["first", "second"])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
    })
  })
  test("tracks intake while normalization is in progress", async () => {
    await withInstance(async () => {
      const sid = "track-intake"
      const work = defer()
      const tracked = IngestQueue.track(sid, () => work.promise, sid)
      expect(IngestQueue.pendingCount(sid)).toBe(1)
      work.resolve()
      await tracked
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

describe("IngestQueue.reserve", () => {
  test("keeps arrival order when a later capture becomes ready first", async () => {
    await withInstance(async () => {
      const sid = "reserved-arrival-order"
      const first = IngestQueue.reserve(sid, sid)
      const second = IngestQueue.reserve(sid, sid)
      const firstStarted = defer()
      const releaseFirst = defer()
      const order: string[] = []

      // Simulate request 2 finishing normalization before request 1.
      IngestQueue.enqueueReserved(second, async () => {
        order.push("second")
      })
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual([])
      expect(IngestQueue.pendingCount(sid)).toBe(2)

      IngestQueue.enqueueReserved(first, async () => {
        order.push("first")
        firstStarted.resolve()
        await releaseFirst.promise
      })
      await firstStarted.promise
      expect(order).toEqual(["first"])
      releaseFirst.resolve()
      await new Promise((r) => setTimeout(r, 15))

      expect(order).toEqual(["first", "second"])
      expect(IngestQueue.pendingCount(sid)).toBe(0)
    })
  })

  test("skipping a deduplicated capture releases its FIFO slot", async () => {
    await withInstance(async () => {
      const sid = "reserved-skip-order"
      const first = IngestQueue.reserve(sid, sid)
      const second = IngestQueue.reserve(sid, sid)
      const order: string[] = []

      IngestQueue.enqueueReserved(second, async () => {
        order.push("second")
      })
      IngestQueue.skipReserved(first)
      await new Promise((r) => setTimeout(r, 15))

      expect(order).toEqual(["second"])
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
  test("explicitly independent child sessions can run concurrently and share parent queue controls", async () => {
    await withInstance(async () => {
      const parent = "parent-parallel-ingest"
      const childA = "child-parallel-ingest-a"
      const childB = "child-parallel-ingest-b"
      const firstStarted = defer()
      const secondStarted = defer()
      const releaseFirst = defer()
      const releaseSecond = defer()
      const order: string[] = []

      IngestQueue.enqueue(parent, async () => {
        firstStarted.resolve()
        await releaseFirst.promise
        order.push(childA)
      }, parent, true)
      await firstStarted.promise

      IngestQueue.enqueue(parent, async () => {
        secondStarted.resolve()
        await releaseSecond.promise
        order.push(childB)
      }, parent, true)

      await secondStarted.promise
      expect(order).toEqual([])
      expect(IngestQueue.pendingCount(parent)).toBe(2)

      releaseSecond.resolve()
      releaseFirst.resolve()
      await new Promise((r) => setTimeout(r, 20))
      expect(order).toHaveLength(2)
      expect(order).toContain(childA)
      expect(order).toContain(childB)
      expect(IngestQueue.pendingCount(parent)).toBe(0)
    })
  })

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

  test("Extension Proxy work persists notes visible to the root while the Main Agent is still running", async () => {
    await withInstance(async () => {
      const parent = "main-agent-shared-notes"
      const proxy = "extension-proxy-shared-notes"
      const targetURL = "https://shared-target.example.test"
      const workspace = await TargetMemory.ensure(targetURL)
      const mainStarted = defer()
      const releaseMain = defer()
      const proxySaved = defer()

      IngestQueue.enqueue(parent, async () => {
        mainStarted.resolve()
        await releaseMain.promise
      })
      await mainStarted.promise

      const reservation = IngestQueue.reserve(proxy, parent)
      IngestQueue.enqueueReserved(reservation, async () => {
        await TargetMemory.addNote(targetURL, {
          kind: "evidence",
          title: "Extension capture evidence",
          content: "The child Proxy session recorded this request observation.",
          source: "extension-proxy-test",
        })
        proxySaved.resolve()
      })

      await proxySaved.promise
      await new Promise((r) => setTimeout(r, 10))
      expect(IngestQueue.pendingCount(parent)).toBe(1)
      expect(TargetMemory.allNotes(workspace.id).some((note) => note.content.includes("child Proxy session"))).toBe(true)

      releaseMain.resolve()
      await new Promise((r) => setTimeout(r, 15))
      expect(IngestQueue.pendingCount(parent)).toBe(0)
    })
  })

  test("Extension Proxy child queue runs alongside Main Agent work", async () => {
    await withInstance(async () => {
      const parent = "main-agent-running"
      const proxy = "extension-proxy-running"
      const mainStarted = defer()
      const proxyStarted = defer()
      const releaseMain = defer()
      const releaseProxy = defer()

      IngestQueue.enqueue(parent, async () => {
        mainStarted.resolve()
        await releaseMain.promise
      })
      await mainStarted.promise

      const reservation = IngestQueue.reserve(proxy)
      IngestQueue.enqueueReserved(reservation, async () => {
        proxyStarted.resolve()
        await releaseProxy.promise
      })

      // The Proxy task must start before the Main Agent task finishes.
      await proxyStarted.promise
      expect(IngestQueue.pendingCount(parent)).toBe(1)
      expect(IngestQueue.pendingCount(proxy)).toBe(1)

      releaseProxy.resolve()
      await new Promise((r) => setTimeout(r, 10))
      expect(IngestQueue.pendingCount(parent)).toBe(1)
      expect(IngestQueue.pendingCount(proxy)).toBe(0)

      releaseMain.resolve()
      await new Promise((r) => setTimeout(r, 10))
      expect(IngestQueue.pendingCount(parent)).toBe(0)
    })
  })

  test("later captures cannot overtake earlier intake while normalization finishes out of order", async () => {
    await withInstance(async () => {
      const parent = "parent-intake-order-barrier"
      const proxy = "proxy-intake-order-barrier"
      // Reserve all tickets synchronously in the order the browser requests arrive.
      const first = IngestQueue.reserveOrder(parent)
      const second = IngestQueue.reserveOrder(parent)
      const third = IngestQueue.reserveOrder(parent)
      const started: number[] = []
      const finished: number[] = []
      const allFinished = defer()

      // Simulate request 3 and 2 finishing preprocessing before request 1.
      // They must wait for the earlier intake tickets before reserving broker work.
      const enqueueAfterPreprocessing = async (
        reservation: IngestQueue.IntakeOrderReservation,
        number: number,
      ) => {
        await reservation.previous
        const brokerSlot = IngestQueue.reserve(proxy)
        IngestQueue.enqueueReserved(brokerSlot, async () => {
          started.push(number)
          await Promise.resolve()
          finished.push(number)
          if (finished.length === 3) allFinished.resolve()
        })
        reservation.release()
      }

      const laterThree = enqueueAfterPreprocessing(third, 3)
      const laterTwo = enqueueAfterPreprocessing(second, 2)
      const earliestOne = enqueueAfterPreprocessing(first, 1)

      await Promise.all([laterThree, laterTwo, earliestOne])
      await allFinished.promise
      for (let attempt = 0; attempt < 20 && IngestQueue.pendingCount(proxy) !== 0; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 0))
      }
      expect(started).toEqual([1, 2, 3])
      expect(finished).toEqual([1, 2, 3])
      expect(IngestQueue.pendingCount(proxy)).toBe(0)
    })
  })

  test("runs ten captured requests automatically in intake FIFO order", async () => {
    await withInstance(async () => {
      const proxy = "proxy-ten-request-fifo"
      const reservations = Array.from({ length: 10 }, () => IngestQueue.reserve(proxy))
      const started: number[] = []
      const finished: number[] = []
      const allFinished = defer()

      reservations.forEach((reservation, index) => {
        const number = index + 1
        IngestQueue.enqueueReserved(reservation, async () => {
          started.push(number)
          await Promise.resolve()
          finished.push(number)
          if (finished.length === 10) allFinished.resolve()
        })
      })

      await allFinished.promise
      for (let attempt = 0; attempt < 20 && IngestQueue.pendingCount(proxy) !== 0; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 0))
      }
      expect(started).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
      expect(finished).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
      expect(IngestQueue.pendingCount(proxy)).toBe(0)
    })
  })

  test("Agent Proxy manual follow-ups stay behind captures but not Main work", async () => {
    await withInstance(async () => {
      const parent = "main-manual-followup-running"
      const proxy = "proxy-manual-followup-running"
      const mainStarted = defer()
      const releaseMain = defer()
      const captureStarted = defer()
      const releaseCapture = defer()
      const manualStarted = defer()
      const order: string[] = []

      IngestQueue.enqueue(parent, async () => {
        mainStarted.resolve()
        await releaseMain.promise
      })
      await mainStarted.promise

      const capture = IngestQueue.reserve(proxy)
      IngestQueue.enqueueReserved(capture, async () => {
        order.push("capture-start")
        captureStarted.resolve()
        await releaseCapture.promise
        order.push("capture-finish")
      })
      IngestQueue.enqueue(proxy, async () => {
        order.push("manual-follow-up")
        manualStarted.resolve()
      })

      await captureStarted.promise
      await new Promise((r) => setTimeout(r, 10))
      expect(order).toEqual(["capture-start"])

      releaseCapture.resolve()
      await manualStarted.promise
      expect(order).toEqual(["capture-start", "capture-finish", "manual-follow-up"])
      for (let attempt = 0; attempt < 20 && IngestQueue.pendingCount(proxy) !== 0; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 0))
      }
      // Both Proxy turns finished while the Main Agent task was still running.
      expect(IngestQueue.pendingCount(parent)).toBe(1)
      expect(IngestQueue.pendingCount(proxy)).toBe(0)

      releaseMain.resolve()
      await new Promise((r) => setTimeout(r, 10))
      expect(IngestQueue.pendingCount(parent)).toBe(0)
    })
  })

  test("parent pause does not gate an independent Extension Proxy queue", async () => {
    await withInstance(async () => {
      const parent = "paused-main-agent"
      const proxy = "unpaused-extension-proxy"
      const started = defer()
      const release = defer()

      IngestQueue.pause(parent)
      const reservation = IngestQueue.reserve(proxy)
      IngestQueue.enqueueReserved(reservation, async () => {
        started.resolve()
        await release.promise
      })

      await started.promise
      expect(IngestQueue.isPaused(parent)).toBe(true)
      expect(IngestQueue.pendingCount(parent)).toBe(0)
      expect(IngestQueue.pendingCount(proxy)).toBe(1)

      release.resolve()
      await new Promise((r) => setTimeout(r, 10))
      expect(IngestQueue.pendingCount(parent)).toBe(0)
      expect(IngestQueue.pendingCount(proxy)).toBe(0)
      IngestQueue.resume(parent)
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
  test("suppresses routine queue/completion chatter but keeps actionable parse errors", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "extension-ingest-visibility-test" })
      await IngestSummary.notice(session.id, "Extension request queued for independent analysis: GET /profile")
      await IngestSummary.notice(session.id, "Extension request analysis completed: GET /profile")
      await IngestSummary.notice(session.id, "Extension request already known (deduplicated): GET /profile — credential/cookie observation was retained; LLM work was not duplicated.")
      await IngestSummary.notice(session.id, "Extension request received again: GET /profile — previous analysis had failed and was requeued.")
      await IngestSummary.notice(session.id, "Extension request rejected before analysis: invalid HTTP request format")

      const messages = await Session.messages({ sessionID: session.id })
      const text = messages.flatMap((message) => message.parts)
        .filter((part) => part.type === "text")
        .map((part) => part.text)

      expect(text).not.toContain("Extension request queued for independent analysis: GET /profile")
      expect(text).not.toContain("Extension request analysis completed: GET /profile")
      expect(text).not.toContain("Extension request already known (deduplicated): GET /profile")
      expect(text).not.toContain("credential/cookie observation was retained")
      expect(text).not.toContain("Extension request received again: GET /profile")
      expect(text).toContain("Extension request rejected before analysis: invalid HTTP request format")
      expect(messages.filter((message) => message.info.role === "user").every((message) => "excludeHistory" in message.info && message.info.excludeHistory)).toBe(true)
      expect(MessageV2.filterExcluded(messages)).toHaveLength(0)
      await Session.remove(session.id)
    })
  })
})

describe("Per-request live analysis transcript entries", () => {
  test("keeps sequential request notices separate while sharing the broker session reference", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "per-request-live-analysis-entry-test" })
      const model = { providerID: "test-provider", modelID: "test-model" }
      const brokerSessionID = "shared-proxy-broker-session"
      const first = await IngestSummary.createLiveNotice({
        sessionID: session.id,
        agent: "proxy-agent",
        model,
        text: "## Captured request — ANALYZING\\nRequest: GET /first",
        requestAnalysis: {
          requestID: "request-first",
          analysisSessionID: brokerSessionID,
          method: "GET",
          url: "https://example.test/first",
        },
      })
      const second = await IngestSummary.createLiveNotice({
        sessionID: session.id,
        agent: "proxy-agent",
        model,
        text: "## Captured request — ANALYZING\\nRequest: GET /second",
        requestAnalysis: {
          requestID: "request-second",
          analysisSessionID: brokerSessionID,
          method: "GET",
          url: "https://example.test/second",
        },
      })

      expect(second.messageID).not.toBe(first.messageID)
      expect(second.partID).not.toBe(first.partID)
      expect(second.requestAnalysis.analysisSessionID).toBe(first.requestAnalysis.analysisSessionID)
      const parentMessages = await Session.messages({ sessionID: session.id })
      expect(parentMessages.filter((message) => message.info.role === "user").every((message) => "excludeHistory" in message.info && message.info.excludeHistory)).toBe(true)
      expect(MessageV2.filterExcluded(parentMessages)).toHaveLength(0)

      await IngestSummary.updateLiveNotice({
        sessionID: session.id,
        live: first,
        text: "First request finished",
        completed: true,
        status: "processed",
      })
      // A late write for a completed request is ignored and cannot overwrite
      // the separate live entry for the next request.
      await IngestSummary.updateLiveNotice({
        sessionID: session.id,
        live: first,
        text: "STALE first request output",
      })
      await IngestSummary.updateLiveNotice({
        sessionID: session.id,
        live: second,
        text: "Second request remains live",
      })

      const messages = await Session.messages({ sessionID: session.id })
      const parts = messages.flatMap((message) => message.parts)
        .filter((part) => part.type === "text" && (part.metadata as { kind?: string } | undefined)?.kind === "ingest-summary")
      expect(parts).toHaveLength(2)
      const texts = parts.filter((part) => part.type === "text").map((part) => part.text)
      expect(texts).toContain("First request finished")
      expect(texts).toContain("Second request remains live")
      expect(texts).not.toContain("STALE first request output")
      await Session.remove(session.id)
    })
  })
})

describe("Request pending recovery query", () => {
  test("returns queued and interrupted processing rows but excludes terminal rows", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "request-pending-recovery-test" })
      const create = (path: string, keyHash: string) => {
        const item = Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: path,
          origin: "https://example.test",
          keyHash,
        })
        if (!item) throw new Error(`request fixture was not inserted: ${path}`)
        return item
      }
      const queued = create("/queued", "pending-queued-key")
      const processing = create("/processing", "pending-processing-key")
      const processed = create("/processed", "pending-processed-key")
      const failed = create("/failed", "pending-failed-key")

      Request.updateStatus({ id: processing.id, status: "processing" })
      Request.updateStatus({ id: processed.id, status: "processed" })
      Request.updateStatus({ id: failed.id, status: "failed" })

      const pending = Request.pending().filter((item) => item.session_id === session.id).map((item) => item.id)
      expect(pending).toContain(queued.id)
      expect(pending).toContain(processing.id)
      expect(pending).not.toContain(processed.id)
      expect(pending).not.toContain(failed.id)
      await Session.remove(session.id)
    })
  })
})

test("request recovery uses intake IDs even when normalization writes rows in reverse order", async () => {
  await withInstance(async () => {
    const session = await Session.create({ title: "request-intake-order-recovery-test" })
    const arrivalIDs = Array.from({ length: 10 }, () => Identifier.ascending("request"))
    for (let index = arrivalIDs.length - 1; index >= 0; index--) {
      const request = Request.add({
        id: arrivalIDs[index],
        sessionID: session.id,
        method: "GET",
        normalizedPath: `/dependency/${index + 1}`,
        origin: "https://example.test",
        keyHash: "same-structural-endpoint",
      })
      expect(request).toBeDefined()
    }
    const recovered = Request.pending().filter((item) => item.session_id === session.id)
    expect(recovered.map((item) => item.id)).toEqual(arrivalIDs)
    expect(recovered.map((item) => item.normalized_path)).toEqual(
      Array.from({ length: 10 }, (_, index) => `/dependency/${index + 1}`),
    )
    await Session.remove(session.id)
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

describe("Request.findEquivalentProcessed", () => {
  test("reuses only an exact completed capture for the same credential and access context", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "request-equivalent-analysis-test" })
      const rawRequest = "GET /api/profile HTTP/1.1\\r\\nHost: example.test\\r\\nAccept: application/json\\r\\n\\r\\n"
      const create = (credentialID: string, body: string, roles: string[] = ["member"]) => {
        const item = Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/api/profile",
          origin: "https://example.test",
          credentialID,
          rawRequest,
          bodyHash: "no-body",
          queryHash: "no-query",
          keyHash: "same-profile-shape",
          elementRoles: roles,
          response: {
            status: 200,
            headers: { "content-type": "application/json" },
            body,
          },
        })
        if (!item) throw new Error("request fixture was not inserted")
        return item
      }

      const owner = create("credential-owner", '{"id":1,"name":"Owner"}')
      Request.updateStatus({ id: owner.id, status: "processed" })
      const ownerRepeat = create("credential-owner", '{"id":1,"name":"Owner"}')
      const lowUser = create("credential-low", '{"id":1,"name":"Owner"}')
      const changedResponse = create("credential-owner", '{"id":1,"name":"Changed"}')
      const changedRole = create("credential-owner", '{"id":1,"name":"Owner"}', ["admin"])

      expect(Request.findEquivalentProcessed(ownerRepeat)?.id).toBe(owner.id)
      expect(Request.findEquivalentProcessed(lowUser)).toBeUndefined()
      expect(Request.findEquivalentProcessed(changedResponse)).toBeUndefined()
      expect(Request.findEquivalentProcessed(changedRole)).toBeUndefined()

      // The second credential and every distinct capture remain independent rows.
      expect(Request.get(session.id).map((item) => item.id)).toEqual([
        owner.id,
        ownerRepeat.id,
        lowUser.id,
        changedResponse.id,
        changedRole.id,
      ])
      await Session.remove(session.id)
    })
  })
})

describe("Request.retryFailed", () => {
  test("requeues a failed request once and refuses queued or processed requests", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "request-retry-failed-test" })
      const create = (path: string, keyHash: string) => {
        const request = Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: path,
          origin: "https://example.test",
          keyHash,
        })
        if (!request) throw new Error(`request fixture was not inserted: ${path}`)
        return request
      }

      const failed = create("/retry-failed", "request-retry-failed-key")
      const queued = create("/retry-queued", "request-retry-queued-key")
      const processed = create("/retry-processed", "request-retry-processed-key")
      Request.updateStatus({ id: failed.id, status: "failed" })
      Request.updateStatus({ id: processed.id, status: "processed" })

      expect(Request.findByKeyHash(session.id, "request-retry-failed-key")).toMatchObject({
        id: failed.id,
        status: "failed",
      })
      expect(Request.findByKeyHash(session.id, "missing-key")).toBeUndefined()

      const retried = Request.retryFailed(session.id, failed.id)
      expect(retried?.status).toBe("queued")
      expect(Request.findByKeyHash(session.id, "request-retry-failed-key")).toMatchObject({
        id: failed.id,
        status: "queued",
      })
      expect(Request.get(session.id).find((item) => item.id === failed.id)?.status).toBe("queued")

      // Once requeued, the same retry cannot enqueue the request a second time.
      expect(Request.retryFailed(session.id, failed.id)).toBeUndefined()
      expect(Request.retryFailed(session.id, queued.id)).toBeUndefined()
      expect(Request.retryFailed(session.id, processed.id)).toBeUndefined()

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


test("preserves JavaScript versions while each captured transaction has its own request row", async () => {
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
    expect(second).toBeDefined()
    expect(second?.id).not.toBe(first?.id)

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
    expect(repeatedBody).toBeDefined()
    expect(repeatedBody?.id).not.toBe(first?.id)
    expect(repeatedBody?.id).not.toBe(second?.id)
    const afterRepeat = Database.use((db) =>
      db.select({ id: RequestJavaScriptCaptureTable.id })
        .from(RequestJavaScriptCaptureTable)
        .where(eq(RequestJavaScriptCaptureTable.session_id, session.id))
        .all(),
    )
    expect(afterRepeat).toHaveLength(3)
    await Session.remove(session.id)
  })
})

describe("captured request payload preservation", () => {
  test("stores every captured header and body byte for later request detail and replay", async () => {
    await withInstance(async () => {
      const previousDryRun = process.env.CYBERSTRIKE_INGEST_DRY_RUN
      process.env.CYBERSTRIKE_INGEST_DRY_RUN = "true"
      let sessionID: string | undefined
      try {
        await TargetMemory.configureScope("https://example.test", {
          include: ["https://example.test"],
          authorizationSource: "Captured request payload preservation test",
          userConfirmed: true,
        })
        const session = await Session.create({ title: "complete-captured-request-test" })
        sessionID = session.id
        const body = JSON.stringify({ marker: "end-of-body-marker", payload: "x".repeat(12 * 1024) })
        const extraHeaders = Array.from(
          { length: 24 },
          (_, index) => "X-Captured-Header-" + String(index).padStart(2, "0") + ": value-" + index,
        ).join("\r\n")
        const rawRequest = [
          "POST /api/profile HTTP/1.1",
          "Host: example.test",
          "Content-Type: application/json",
          extraHeaders,
          "Content-Length: " + Buffer.byteLength(body, "utf8"),
          "",
          body,
        ].join("\r\n")

        const response = await Server.App().request(
          "/session/ingest?directory=" + encodeURIComponent(Instance.directory),
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: rawRequest, sessionID: session.id, scheme: "https" }),
          },
        )

        expect(response.status, `ingest rejection response: ${await response.clone().text()}`).toBe(202)
        const stored = Request.get(session.id).find((item) => item.raw_request)
        expect(stored?.raw_request).toBe(rawRequest)
        expect(stored?.raw_request).toContain("X-Captured-Header-23: value-23")
        expect(stored?.raw_request).toContain('"marker":"end-of-body-marker"')
        expect(stored?.raw_request).toContain("x".repeat(12 * 1024))

        // A repeated HTTP transaction with the same endpoint/body is still its own
        // Request row and must be offered to the Agent Proxy for independent analysis.
        const duplicateResponse = await Server.App().request(
          "/session/ingest?directory=" + encodeURIComponent(Instance.directory),
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: rawRequest, sessionID: session.id, scheme: "https" }),
          },
        )
        expect(duplicateResponse.status, await duplicateResponse.clone().text()).toBe(202)
        const capturedRows = Request.get(session.id).filter((item) => item.raw_request === rawRequest)
        expect(capturedRows).toHaveLength(2)
        expect(new Set(capturedRows.map((item) => item.id)).size).toBe(2)
      } finally {
        if (sessionID) await Session.remove(sessionID).catch(() => {})
        if (previousDryRun === undefined) delete process.env.CYBERSTRIKE_INGEST_DRY_RUN
        else process.env.CYBERSTRIKE_INGEST_DRY_RUN = previousDryRun
      }
    })
  })
})

describe("captured request HTTP route scope gate", () => {
  test("creates exactly one Agent Proxy child under the selected parent and reuses it for later captures", async () => {
    await withInstance(async () => {
      const previousDryRun = process.env.CYBERSTRIKE_INGEST_DRY_RUN
      delete process.env.CYBERSTRIKE_INGEST_DRY_RUN
      const parent = await Session.create({ title: "proxy-child-session-parent-test" })
      try {
        await TargetMemory.configureScope("https://program-proxy-child.example.test", {
          include: ["https://proxy-child-app.example.test/"],
          authorizationSource: "Agent Proxy child-session integration test",
          userConfirmed: true,
        })

        const capture = async (path: string) => Server.App().request(
          "/session/ingest?directory=" + encodeURIComponent(Instance.directory),
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              sessionID: parent.id,
              scheme: "https",
              text: "GET " + path + " HTTP/1.1\r\nHost: proxy-child-app.example.test\r\n\r\n",
            }),
          },
        )

        const first = await capture("/profile")
        expect(first.status, await first.clone().text()).toBe(202)
        let children = await Session.children(parent.id)
        for (let attempt = 0; attempt < 30 && !children.some((child) => child.title === "Agent Proxy"); attempt++) {
          await new Promise((resolve) => setTimeout(resolve, 10))
          children = await Session.children(parent.id)
        }
        const broker = children.find((child) => child.title === "Agent Proxy")
        expect(broker, "the ingest route must create the Agent Proxy child session").toBeDefined()
        expect(broker?.parentID).toBe(parent.id)

        // Concurrent captures must share the same child, not race into duplicate
        // Agent Proxy sessions under one selected parent.
        const concurrent = await Promise.all([capture("/settings"), capture("/billing")])
        for (const response of concurrent) {
          expect(response.status, await response.clone().text()).toBe(202)
        }
        const afterConcurrent = await Session.children(parent.id)
        const brokers = afterConcurrent.filter((child) => child.title === "Agent Proxy")
        expect(brokers).toHaveLength(1)
        expect(brokers[0]?.id).toBe(broker?.id)
        expect(brokers[0]?.parentID).toBe(parent.id)
        expect(Request.get(parent.id)).toHaveLength(3)
      } finally {
        const children = await Session.children(parent.id).catch(() => [])
        for (const child of children) await Session.remove(child.id).catch(() => {})
        await Session.remove(parent.id).catch(() => {})
        if (previousDryRun === undefined) delete process.env.CYBERSTRIKE_INGEST_DRY_RUN
        else process.env.CYBERSTRIKE_INGEST_DRY_RUN = previousDryRun
      }
    })
  })

  test("rejects an out-of-scope request before creating a request record or proxy broker", async () => {
    await withInstance(async () => {
      const session = await Session.create({ title: "ingest-scope-gate-test" })
      try {
        await TargetMemory.configureScope("https://program-root.example.test", {
          include: ["https://authorized-app.example.test/safe"],
          authorizationSource: "Session ingest route scope-gate test",
          userConfirmed: true,
        })

        const response = await Server.App().request(
          "/session/ingest?directory=" + encodeURIComponent(Instance.directory),
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              sessionID: session.id,
              scheme: "https",
              text: "GET /admin/profile HTTP/1.1\\r\\nHost: authorized-app.example.test\\r\\n\\r\\n",
            }),
          },
        )

        expect(response.status).toBe(403)
        expect(Request.get(session.id)).toHaveLength(0)
        expect(await Session.children(session.id)).toHaveLength(0)
      } finally {
        await Session.remove(session.id).catch(() => {})
      }
    })
  })
})
