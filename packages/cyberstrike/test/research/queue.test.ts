test("research queue enqueue is idempotent for an already-seen source URL", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const first = ResearchQueue.enqueue({
        sourceID: "test-dedupe",
        sourceURL: "https://research.example.test/report?id=123",
        title: "First title",
      })
      const second = ResearchQueue.enqueue({
        sourceID: "test-dedupe",
        sourceURL: "https://research.example.test/report?id=123",
        title: "Updated title should not create a duplicate",
      })
      expect(first.created).toBe(true)
      expect(second.created).toBe(false)
      expect(second.sequence).toBe(first.sequence)
      expect(ResearchQueue.stats("test-dedupe").total).toBe(1)
      // Leave no queued work behind: other queue tests deliberately claim the oldest item.
      const cleanupClaim = ResearchQueue.claimNext("dedupe-test-cleanup")
      expect(cleanupClaim?.sequence).toBe(first.sequence)
      ResearchQueue.complete(cleanupClaim!.sequence, cleanupClaim!.lease_owner, "learned")
      await Instance.dispose()
    },
  })
})

import { expect, test } from "bun:test"
import { ResearchQueue } from "../../src/research/queue"
import { Database, eq } from "../../src/storage/db"
import { ResearchQueueTable } from "../../src/research/queue.sql"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

test("research queue only accepts completion from the current lease owner", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const item = ResearchQueue.enqueue({ sourceID: "test", sourceURL: "https://research.example.test/one" })
      const claim = ResearchQueue.claimNext("worker-a", "test")
      expect(claim?.sequence).toBe(item.sequence)
      const leaseOwner = claim?.lease_owner
      expect(leaseOwner?.startsWith("worker-a:")).toBe(true)
      if (!leaseOwner) throw new Error("claimed research item did not include its lease token")
      expect(ResearchQueue.complete(item.sequence, "worker-b", "learned")).toBeUndefined()
      const current = Database.use((db) => db.select().from(ResearchQueueTable).where(eq(ResearchQueueTable.sequence, item.sequence)).get())
      expect(current?.lease_owner).toBe(leaseOwner)
      expect(ResearchQueue.complete(item.sequence, leaseOwner, "learned")?.status).toBe("learned")
      await Instance.dispose()
    },
  })
})

test("research queue reclaims legacy studying rows with no lease expiry", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const item = ResearchQueue.enqueue({ sourceID: "test", sourceURL: "https://research.example.test/legacy-studying" })
      Database.use((db) =>
        db.update(ResearchQueueTable)
          .set({ status: "studying", lease_owner: null, lease_until: null })
          .where(eq(ResearchQueueTable.sequence, item.sequence))
          .run(),
      )

      const reclaimed = ResearchQueue.claimNext("recovery-worker", "test")
      expect(reclaimed?.sequence).toBe(item.sequence)
      expect(reclaimed?.lease_owner?.startsWith("recovery-worker:")).toBe(true)
      expect(reclaimed?.lease_until).toBeGreaterThan(Date.now())
      await Instance.dispose()
    },
  })
})

test("an expired lease can be reclaimed and the stale worker cannot complete it", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const item = ResearchQueue.enqueue({ sourceID: "test", sourceURL: "https://research.example.test/stale-worker" })
      const firstClaim = ResearchQueue.claimNext("same-worker", "test")
      expect(firstClaim?.sequence).toBe(item.sequence)
      const firstLease = firstClaim?.lease_owner
      expect(firstLease?.startsWith("same-worker:")).toBe(true)
      if (!firstLease) throw new Error("first claim did not include its lease token")

      Database.use((db) =>
        db.update(ResearchQueueTable)
          .set({ lease_until: Date.now() - 1 })
          .where(eq(ResearchQueueTable.sequence, item.sequence))
          .run(),
      )
      const reclaimed = ResearchQueue.claimNext("same-worker", "test")
      expect(reclaimed?.sequence).toBe(item.sequence)
      const reclaimedLease = reclaimed?.lease_owner
      expect(reclaimedLease?.startsWith("same-worker:")).toBe(true)
      if (!reclaimedLease) throw new Error("reclaimed item did not include its lease token")
      expect(reclaimedLease).not.toBe(firstLease)

      expect(ResearchQueue.complete(item.sequence, firstLease, "learned")).toBeUndefined()
      const current = Database.use((db) =>
        db.select().from(ResearchQueueTable).where(eq(ResearchQueueTable.sequence, item.sequence)).get(),
      )
      expect(current?.lease_owner).toBe(reclaimedLease)
      expect(ResearchQueue.complete(item.sequence, reclaimedLease, "learned")?.status).toBe("learned")
      await Instance.dispose()
    },
  })
})


test("research queue records auth-blocked work and only retries it explicitly", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const blocked = ResearchQueue.blockAuthentication({
        sourceID: "test-auth",
        sourceURL: "https://research.example.test/private-report",
        reason: "HTTP 401",
      })
      expect(blocked?.status).toBe("blocked_auth")
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.last_error).toBe("HTTP 401")
      expect(ResearchQueue.claimNext("worker-auth", "test-auth")).toBeNull()
      expect(ResearchQueue.retryAuthenticationBlocked(10, "test-auth")).toBe(1)
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.status).toBe("queued")
      const claimed = ResearchQueue.claimNext("worker-auth", "test-auth")
      expect(claimed?.status).toBe("studying")
      expect(claimed?.attempts).toBe(1)
      ResearchQueue.complete(claimed!.sequence, claimed!.lease_owner, "blocked_auth", "HTTP 401")
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.attempts).toBe(1)
      expect(ResearchQueue.retryAuthenticationBlocked(10, "test-auth")).toBe(1)
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.attempts).toBe(0)
      await Instance.dispose()
    },
  })
})


test("source-filtered queue claims never consume another source's work", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const other = ResearchQueue.enqueue({ sourceID: "other-source", sourceURL: "https://other.example.test/report" })
      const wanted = ResearchQueue.enqueue({ sourceID: "wanted-source", sourceURL: "https://wanted.example.test/report" })
      const claim = ResearchQueue.claimNext("filtered-worker", "wanted-source")
      expect(claim?.sequence).toBe(wanted.sequence)
      expect(claim?.source_id).toBe("wanted-source")
      expect(ResearchQueue.find("other-source", "https://other.example.test/report")?.status).toBe("queued")
      expect(ResearchQueue.complete(wanted.sequence, claim!.lease_owner, "learned")?.status).toBe("learned")
      expect(other.created).toBe(true)
      await Instance.dispose()
    },
  })
})


test("research crawl-page cache skips recent index pages and promotes newly relevant URLs", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const url = "https://research.example.test/archive?page=2"
      const visited = ResearchQueue.markVisitedPage({
        sourceID: "test-crawl-cache",
        sourceURL: url,
        title: "Archive page",
        contentFingerprint: "fingerprint-1",
      })
      expect(visited?.status).toBe("discovered")
      expect(ResearchQueue.isFreshCrawlPage("test-crawl-cache", url)).toBe(true)
      expect(ResearchQueue.isFreshCrawlPage("test-crawl-cache", url, Date.now() + 7 * 60 * 60_000)).toBe(false)
      expect(ResearchQueue.stats("test-crawl-cache").total).toBe(0)
      expect(ResearchQueue.stats("test-crawl-cache").crawl_pages).toBe(1)

      const promoted = ResearchQueue.enqueue({
        sourceID: "test-crawl-cache",
        sourceURL: url,
        title: "Newly relevant report",
        payload: { cached_text: "report content" },
      })
      expect(promoted.created).toBe(true)
      expect(ResearchQueue.find("test-crawl-cache", url)?.status).toBe("queued")
      expect(ResearchQueue.find("test-crawl-cache", url)?.payload?.crawl_page).not.toBe(true)
      expect(ResearchQueue.stats("test-crawl-cache").total).toBe(1)
      expect(ResearchQueue.stats("test-crawl-cache").crawl_pages).toBe(0)
      await Instance.dispose()
    },
  })
})
