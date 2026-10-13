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
import { RESEARCH_LEARNING_VERSION } from "../../src/research/sources"
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
        payload: { cached_text: "Sign in to continue", crawl_depth: 1 },
      })
      expect(blocked?.status).toBe("blocked_auth")
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.last_error).toBe("HTTP 401")
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.payload).not.toHaveProperty("cached_text")
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.payload?.auth_required).toBe(true)
      expect(ResearchQueue.claimNext("worker-auth", "test-auth")).toBeNull()
      expect(ResearchQueue.retryAuthenticationBlocked(10, "test-auth")).toBe(1)
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.status).toBe("queued")
      expect(ResearchQueue.find("test-auth", "https://research.example.test/private-report")?.payload?.auth_required).toBeUndefined()
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
        discoveredLinks: ["https://research.example.test/archive?page=3", "https://research.example.test/writeup/idor"],
      })
      expect(visited?.status).toBe("discovered")
      expect(visited?.payload?.discovered_links).toEqual([
        "https://research.example.test/archive?page=3",
        "https://research.example.test/writeup/idor",
      ])
      expect(ResearchQueue.isFreshCrawlPage("test-crawl-cache", url)).toBe(true)
      expect(ResearchQueue.isFreshCrawlPage("test-crawl-cache", url, Date.now() + 7 * 60 * 60_000)).toBe(false)
      expect(ResearchQueue.stats("test-crawl-cache").total).toBe(0)
      expect(ResearchQueue.stats("test-crawl-cache").crawl_pages).toBe(1)
      expect(ResearchQueue.stats("test-crawl-cache").crawl_page_errors).toBe(0)
      expect(ResearchQueue.stats("test-crawl-cache").crawl_page_auth_blocked).toBe(0)

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


test("failed crawl pages get a cooldown and recover without becoming report work", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sourceID = "crawl-failure-" + marker
      const failedURL = "https://research.example.test/" + marker + "/unavailable-index"

      const failed = ResearchQueue.markFailedCrawlPage({
        sourceID,
        sourceURL: failedURL,
        title: "Temporary network failure",
        reason: "ECONNRESET while reading public research page",
      })
      expect(failed?.status).toBe("discovered")
      expect(failed?.payload?.crawl_page).toBe(true)
      expect(failed?.payload?.crawl_error).toBe(true)
      expect(failed?.last_error).toContain("ECONNRESET")
      expect(ResearchQueue.isFreshCrawlPage(sourceID, failedURL)).toBe(true)
      expect(ResearchQueue.isFreshCrawlPage(sourceID, failedURL, Date.now() + 7 * 60 * 60_000)).toBe(false)
      expect(ResearchQueue.stats(sourceID).total).toBe(0)
      expect(ResearchQueue.stats(sourceID).crawl_pages).toBe(1)
      expect(ResearchQueue.stats(sourceID).crawl_page_errors).toBe(1)

      const recovered = ResearchQueue.markVisitedPage({
        sourceID,
        sourceURL: failedURL,
        title: "Recovered index",
        contentFingerprint: "recovered-content",
      })
      expect(recovered?.status).toBe("discovered")
      expect(recovered?.payload?.crawl_error).toBeUndefined()
      expect(recovered?.last_error).toBeNull()
      expect(ResearchQueue.isFreshCrawlPage(sourceID, failedURL)).toBe(true)

      const failedReportURL = "https://research.example.test/" + marker + "/possible-report"
      ResearchQueue.markFailedCrawlPage({
        sourceID,
        sourceURL: failedReportURL,
        reason: "HTTP 503",
      })
      const promoted = ResearchQueue.enqueue({
        sourceID,
        sourceURL: failedReportURL,
        title: "Recovered report candidate",
        payload: { cached_text: "A sufficiently useful research report body." },
      })
      expect(promoted.created).toBe(true)
      expect(ResearchQueue.find(sourceID, failedReportURL)?.status).toBe("queued")
      expect(ResearchQueue.find(sourceID, failedReportURL)?.payload?.crawl_page).not.toBe(true)
      expect(ResearchQueue.find(sourceID, failedReportURL)?.payload?.crawl_error).toBeUndefined()
      await Instance.dispose()
    },
  })
})

test("retry-auth sends blocked crawl pages back to discovery instead of the learning queue", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const url = "https://research.example.test/archive"
      ResearchQueue.markVisitedPage({ sourceID: "auth-crawl", sourceURL: url, title: "Archive" })
      ResearchQueue.blockAuthentication({
        sourceID: "auth-crawl",
        sourceURL: url,
        reason: "HTTP 401",
        payload: { source_name: "Auth Crawl" },
      })
      expect(ResearchQueue.find("auth-crawl", url)?.status).toBe("blocked_auth")
      expect(ResearchQueue.retryAuthenticationBlocked(10, "auth-crawl")).toBe(1)
      const row = ResearchQueue.find("auth-crawl", url)
      expect(row?.status).toBe("discovered")
      expect(row?.payload?.crawl_page).toBe(true)
      expect(row?.payload?.auth_required).toBeUndefined()
      expect(ResearchQueue.isFreshCrawlPage("auth-crawl", url)).toBe(false)
      expect(ResearchQueue.claimNext("worker-auth-crawl", "auth-crawl")).toBeNull()
      await Instance.dispose()
    },
  })
})


test("a successful crawl revisit clears stale auth markers from an index page", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const sourceID = "auth-crawl-revisit"
      const url = "https://research.example.test/private-archive"
      ResearchQueue.markVisitedPage({ sourceID, sourceURL: url, title: "Private archive" })
      ResearchQueue.blockAuthentication({
        sourceID,
        sourceURL: url,
        reason: "HTTP 401",
        payload: { source_name: "Auth Crawl Revisit" },
      })
      expect(ResearchQueue.find(sourceID, url)?.status).toBe("blocked_auth")
      expect(ResearchQueue.find(sourceID, url)?.payload?.auth_required).toBe(true)

      const revisited = ResearchQueue.markVisitedPage({
        sourceID,
        sourceURL: url,
        title: "Private archive after login",
        contentFingerprint: "authenticated-index",
      })
      expect(revisited?.status).toBe("discovered")
      expect(revisited?.payload?.crawl_page).toBe(true)
      expect(revisited?.payload?.auth_required).toBeUndefined()
      expect(revisited?.payload).not.toHaveProperty("cached_text")
      expect(ResearchQueue.isFreshCrawlPage(sourceID, url)).toBe(true)
      await Instance.dispose()
    },
  })
})

test("automatic auth retry cooldown prevents every watch cycle from refetching invalid sessions", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const url = "https://research.example.test/private-report"
      ResearchQueue.blockAuthentication({ sourceID: "auth-cooldown", sourceURL: url, reason: "HTTP 401" })
      expect(ResearchQueue.retryAuthenticationBlocked(10, "auth-cooldown", 10 * 60_000)).toBe(0)
      // Explicit retry-auth intentionally bypasses the cooldown after the operator changes credentials.
      expect(ResearchQueue.retryAuthenticationBlocked(10, "auth-cooldown")).toBe(1)
      expect(ResearchQueue.find("auth-cooldown", url)?.status).toBe("queued")
      await Instance.dispose()
    },
  })
})


test("research queue survives an application restart and resumes cached report work", async () => {
  await using dir = await tmpdir({ git: true })
  const sourceID = "portswigger"
  const sourceURL = "https://portswigger.net/web-security/access-control/idor"
  let sequence = 0

  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const row = ResearchQueue.enqueue({
        sourceID,
        sourceURL,
        title: "Persisted IDOR report",
        payload: { cached_text: "sanitized report body", content_fingerprint: "stable-fingerprint" },
      })
      sequence = row.sequence
      expect(ResearchQueue.find(sourceID, sourceURL)?.status).toBe("queued")
      await Instance.dispose()
    },
  })

  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const resumed = ResearchQueue.find(sourceID, sourceURL)
      expect(resumed?.sequence).toBe(sequence)
      expect(resumed?.status).toBe("queued")
      expect(resumed?.payload?.cached_text).toBe("sanitized report body")
      expect(resumed?.payload?.content_fingerprint).toBe("stable-fingerprint")
      const claimed = ResearchQueue.claimNext("restart-worker", sourceID)
      expect(claimed?.sequence).toBe(sequence)
      expect(claimed?.status).toBe("studying")
      expect(claimed?.payload?.cached_text).toBe("sanitized report body")
      await Instance.dispose()
    },
  })
})


test("legacy classifier rejections with cached text are requeued once per learning version", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const sourceID = "legacy-relearn-" + crypto.randomUUID()
      const sourceURL = "https://research.example.test/legacy-relearn-" + crypto.randomUUID()
      const cachedText = [
        "Mass-assignment in a user profile endpoint allowed a client-supplied role to be updated.",
        "Prerequisite: use a controlled test account and capture the normal profile update request.",
        "Reproduction: compare the permitted update fields with fields accepted by the server.",
        "Impact: a user may modify a protected account property when server-side allowlisting is missing.",
      ].join(" ").repeat(3)
      const item = ResearchQueue.enqueue({
        sourceID,
        sourceURL,
        title: "Legacy mass assignment report",
        payload: { cached_text: cachedText },
      })
      // Simulate a pre-versioned item rejected by the earlier, narrower classifier.
      Database.use((db) => db.update(ResearchQueueTable).set({
        status: "rejected",
        last_error: "no recognizable security topic",
        payload: { cached_text: cachedText },
      }).where(eq(ResearchQueueTable.sequence, item.sequence)).run())

      expect(ResearchQueue.requeueLegacyRejected(10, sourceID)).toBe(1)
      const requeued = ResearchQueue.find(sourceID, sourceURL)
      expect(requeued?.status).toBe("queued")
      expect(requeued?.payload?.learning_version).toBe(RESEARCH_LEARNING_VERSION)
      expect(ResearchQueue.requeueLegacyRejected(10, sourceID)).toBe(0)

      const claim = ResearchQueue.claimNext("legacy-relearn-worker", sourceID)
      expect(claim?.sequence).toBe(item.sequence)
      expect(claim?.payload?.learning_version).toBe(RESEARCH_LEARNING_VERSION)
      expect(ResearchQueue.complete(item.sequence, claim!.lease_owner, "rejected", "no recognizable security topic")).toBeDefined()
      // A current-version rejection remains terminal until the learner version changes.
      expect(ResearchQueue.requeueLegacyRejected(10, sourceID)).toBe(0)
      await Instance.dispose()
    },
  })
})

test("an expired learner cannot block authentication over a reclaimed lease", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const url = "https://research.example.test/late-login-wall"
      const item = ResearchQueue.enqueue({ sourceID: "auth-lease-fence", sourceURL: url })
      const first = ResearchQueue.claimNext("late-worker", "auth-lease-fence")
      if (!first) throw new Error("first worker did not claim the queue item")

      Database.use((db) =>
        db.update(ResearchQueueTable)
          .set({ lease_until: Date.now() - 1 })
          .where(eq(ResearchQueueTable.sequence, item.sequence))
          .run(),
      )
      const current = ResearchQueue.claimNext("replacement-worker", "auth-lease-fence")
      if (!current) throw new Error("replacement worker did not reclaim the queue item")

      expect(ResearchQueue.blockAuthentication({
        sourceID: "auth-lease-fence",
        sourceURL: url,
        reason: "late worker observed a login wall",
        claim: { sequence: item.sequence, leaseOwner: first.lease_owner },
      })).toBeUndefined()

      const row = ResearchQueue.find("auth-lease-fence", url)
      expect(row?.status).toBe("studying")
      expect(row?.lease_owner).toBe(current.lease_owner)
      expect(ResearchQueue.complete(item.sequence, current.lease_owner, "learned")?.status).toBe("learned")
      await Instance.dispose()
    },
  })
})

test("an expired lease cannot complete work before another worker reclaims it", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const item = ResearchQueue.enqueue({ sourceID: "test", sourceURL: "https://research.example.test/expired-without-reclaim" })
      const claim = ResearchQueue.claimNext("late-worker", "test")
      expect(claim?.sequence).toBe(item.sequence)
      const leaseOwner = claim?.lease_owner
      if (!leaseOwner) throw new Error("claim did not include its lease token")

      Database.use((db) =>
        db.update(ResearchQueueTable)
          .set({ lease_until: Date.now() - 1 })
          .where(eq(ResearchQueueTable.sequence, item.sequence))
          .run(),
      )

      expect(ResearchQueue.complete(item.sequence, leaseOwner, "learned")).toBeUndefined()
      const current = Database.use((db) =>
        db.select().from(ResearchQueueTable).where(eq(ResearchQueueTable.sequence, item.sequence)).get(),
      )
      expect(current?.status).toBe("studying")
      expect(current?.lease_owner).toBe(leaseOwner)

      const recovered = ResearchQueue.claimNext("recovery-worker", "test")
      expect(recovered?.sequence).toBe(item.sequence)
      const recoveredLease = recovered?.lease_owner
      if (!recoveredLease) throw new Error("recovered claim did not include its lease token")
      expect(recoveredLease).not.toBe(leaseOwner)
      expect(ResearchQueue.complete(item.sequence, leaseOwner, "learned")).toBeUndefined()
      expect(ResearchQueue.complete(item.sequence, recoveredLease, "learned")?.status).toBe("learned")
      await Instance.dispose()
    },
  })
})

