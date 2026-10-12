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
      const claim = ResearchQueue.claimNext("worker-a")
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

      const reclaimed = ResearchQueue.claimNext("recovery-worker")
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
      const firstClaim = ResearchQueue.claimNext("same-worker")
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
      const reclaimed = ResearchQueue.claimNext("same-worker")
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
      expect(ResearchQueue.claimNext("worker-auth")).toBeNull()
      expect(ResearchQueue.retryAuthenticationBlocked(10, "test-auth")).toBe(1)
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.status).toBe("queued")
      expect(ResearchQueue.claimNext("worker-auth")?.status).toBe("studying")
      await Instance.dispose()
    },
  })
})
