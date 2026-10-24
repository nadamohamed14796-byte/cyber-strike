import { describe, expect, test } from "bun:test"
import path from "path"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Intel } from "../../src/methodology/intel"
import { Log } from "../../src/util/log"

const projectRoot = path.join(__dirname, "../..")
Log.init({ print: false })

describe("Intel — CRUD", () => {
  test("add creates entry and returns it", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})
        const entry = Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /api/users",
            detail: "User listing endpoint",
            asset: "api.example.com",
            source: "web-application",
            confidenceLevel: "confirmed",
            tags: ["api", "user"],
          },
        })

        expect(entry.title).toBe("GET /api/users")
        expect(entry.type).toBe("endpoint")
        expect(entry.asset).toBe("api.example.com")

        await Session.remove(session.id)
      },
    })
  })

  test("dedup by title+asset prevents duplicates", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        const first = Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /api/users",
            detail: "User listing endpoint",
            asset: "api.example.com",
            source: "web-application",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        const second = Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "high",
            title: "GET /api/users",
            detail: "Updated detail",
            asset: "api.example.com",
            source: "web-application",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        // Second add should return the same entry (dedup)
        expect(second.id).toBe(first.id)

        await Session.remove(session.id)
      },
    })
  })

  test("dedupes differently titled intel when the same redacted fingerprint is reported for the same asset", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})
        const fingerprint = "abcdef0123456789abcdef01"
        const first = Intel.add({
          sessionID: session.id,
          data: {
            type: "configuration",
            title: "Client-side API key exposed",
            detail: "Source: app.js:12; fingerprint sha256:" + fingerprint,
            asset: "app.example.com",
            source: "javascript-analysis",
            confidenceLevel: "low",
            tags: ["javascript"],
          },
        })
        const second = Intel.add({
          sessionID: session.id,
          data: {
            type: "configuration",
            title: "Potential Google API key exposure",
            detail: "Source: app.js:12; fingerprint sha256:" + fingerprint,
            asset: "app.example.com",
            source: "javascript-analysis",
            confidenceLevel: "low",
            tags: ["javascript"],
          },
        })
        expect(second.id).toBe(first.id)
        expect(second.duplicate).toBe(true)
        const differentFingerprint = Intel.add({
          sessionID: session.id,
          data: {
            type: "configuration",
            title: "Different client-side key exposure",
            detail: "Source: app.js:13; fingerprint sha256:0123456789abcdef01234567",
            asset: "app.example.com",
            source: "javascript-analysis",
            confidenceLevel: "low",
            tags: ["javascript"],
          },
        })
        expect(differentFingerprint.id).not.toBe(first.id)
        await Session.remove(session.id)
      },
    })
  })

  test("different assets are not deduped", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        const first = Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /api/users",
            detail: "First asset",
            asset: "api.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        const second = Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /api/users",
            detail: "Second asset",
            asset: "api2.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        expect(second.id).not.toBe(first.id)

        await Session.remove(session.id)
      },
    })
  })

  test("get returns all entries for session", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /api/users",
            detail: "Users endpoint",
            asset: "api.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        Intel.add({
          sessionID: session.id,
          data: {
            type: "subdomain",
            severity: "info",
            title: "admin.example.com",
            detail: "Admin subdomain",
            asset: "example.com",
            source: "test",
            confidenceLevel: "high",
            tags: [],
          },
        })

        const entries = Intel.get(session.id)
        expect(entries.length).toBe(2)

        await Session.remove(session.id)
      },
    })
  })

  test("getByAsset filters by asset", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "Endpoint 1",
            detail: "Detail",
            asset: "api.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "Endpoint 2",
            detail: "Detail",
            asset: "other.example.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        const filtered = Intel.getByAsset(session.id, "api.example.com")
        expect(filtered.length).toBe(1)
        expect(filtered[0].title).toBe("Endpoint 1")

        await Session.remove(session.id)
      },
    })
  })
})

describe("Intel — VRT Checklist", () => {
  test("auto-generates VRT checks for endpoint type", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "POST /api/transfer",
            detail: "Fund transfer endpoint",
            asset: "api.bank.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        const checks = Intel.getVrtChecks(session.id)
        expect(checks.length).toBeGreaterThan(0)

        // Endpoint type should generate VRT checks for common categories
        const categories = checks.map((c) => c.category)
        expect(categories.some((c) => c.includes("IDOR") || c.includes("Auth") || c.includes("XSS"))).toBe(true)

        await Session.remove(session.id)
      },
    })
  })
})

describe("Intel — Coverage", () => {
  test("computeCoverage returns zero for empty session", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        const coverage = Intel.computeCoverage(session.id)
        expect(coverage.totalChecks).toBe(0)
        expect(coverage.coveragePercent).toBe(0)

        await Session.remove(session.id)
      },
    })
  })

  test("computeCoverage counts completed checks", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const session = await Session.create({})

        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            severity: "medium",
            title: "GET /api/test",
            detail: "Test endpoint",
            asset: "test.com",
            source: "test",
            confidenceLevel: "confirmed",
            tags: [],
          },
        })

        const checks = Intel.getVrtChecks(session.id)
        expect(checks.length).toBeGreaterThan(0)

        // Mark first check as tested
        if (checks.length > 0) {
          Intel.updateVrtCheck(session.id, checks[0].entryID, checks[0].category, {
            status: "tested_not_vulnerable",
            technique: "Manual testing",
            testedBy: "test-agent",
            evidence: { reasoning: "Tested and found not vulnerable" },
          })
        }

        const coverage = Intel.computeCoverage(session.id)
        expect(coverage.completedChecks).toBeGreaterThan(0)
        expect(coverage.coveragePercent).toBeGreaterThan(0)

        await Session.remove(session.id)
      },
    })
  })
})
