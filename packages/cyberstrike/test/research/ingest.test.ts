import { expect, test } from "bun:test"
import { eq } from "drizzle-orm"
import { Database } from "../../src/storage/db"
import { ResearchQueueTable } from "../../src/research/queue.sql"
import { extractResearchDetails, learnResearchQueue, looksLikeResearchAuthenticationWall, normalizeResearchUrl, redactResearchSecrets, retryAuthenticatedResearch } from "../../src/research/ingest"
import { ResearchQueue } from "../../src/research/queue"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

test("research extraction keeps reproduction, prerequisites, verification, caveats, PoC, and retrieval signals", () => {
  const extracted = extractResearchDetails(
    "IDOR exposes an API object",
    [
      "Prerequisite: the tester has two controlled accounts with different object ownership.",
      "Step 1: sign in as the first account and capture the request to GET /api/objects/123.",
      "Then change the object identifier and send the request from the second account.",
      "Verify the response body and compare it with the owner-account baseline.",
      "False positive caution: a public object identifier alone does not prove unauthorized access.",
      "curl -i https://app.example.test/api/objects/123",
      "The issue allows another user to read a private object when object-level authorization is missing.",
    ].join("\n"),
    "idor",
  )

  expect(extracted.severity).toBe("unknown")
  expect(extracted.lesson).toContain("authorization")
  expect(extracted.reproduction).toContain("Step 1")
  expect(extracted.prerequisites).toContain("two controlled accounts")
  expect(extracted.verificationSignals).toContain("Verify the response")
  expect(extracted.falsePositiveCautions).toContain("does not prove")
  expect(extracted.rootCause).toContain("authorization is missing")
  expect(extracted.requestResponseEvidence).toContain("GET /api/objects/123")
  expect(extracted.affectedComponents).toContain("API")
  expect(extracted.technologyStack).toBeUndefined()
  expect(extracted.remediation).toBeUndefined()
  expect(extracted.poc).toContain("curl -i")
  expect(extracted.retrievalSignals).toContain("idor")
  expect(extracted.retrievalSignals).toContain("authorization-boundary")
  expect(extracted.retrievalSignals).toContain("api-endpoint")
  expect(extracted.retrievalSignals).toContain("object-identifier")
})

test("research extraction preserves remediation, version, stack, and negative evidence when present", () => {
  const extracted = extractResearchDetails(
    "Vulnerable API route in Express",
    [
      "Affected versions: Express 4.18.0 through 4.18.2 are vulnerable.",
      "The issue occurs in the Node.js Express middleware when the authorization check is missing.",
      "The researcher could not reproduce the issue after applying the patch.",
      "Remediation: upgrade to the patched release and enforce authorization on every object request.",
      "The attack chain combines a source map disclosure with an IDOR that leads to account data exposure.",
    ].join("\n"),
  )
  expect(extracted.affectedVersions).toContain("Affected versions")
  expect(extracted.technologyStack).toContain("Express")
  expect(extracted.negativeEvidence).toContain("could not reproduce")
  expect(extracted.remediation).toContain("upgrade to the patched release")
  expect(extracted.attackChain).toContain("attack chain")
})


test("research PoC extraction recognizes HTTPie and Python HTTP-client examples", async () => {
  const extracted = (await import("../../src/research/ingest")).extractResearchDetails(
    "Authenticated API object access",
    [
      "http --follow GET https://app.example.test/api/objects/123",
      "requests.get('https://app.example.test/api/objects/123', headers=headers)",
      "httpx.post('https://app.example.test/api/transfer', json=payload)",
    ].join(" "),
    "idor",
  )
  expect(extracted.poc).toContain("http --follow GET https://app.example.test/api/objects/123")
  expect(extracted.poc).toContain("requests.get(")
  expect(extracted.poc).toContain("httpx.post(")
})

test("research ingestion redacts credentials and secret-bearing URLs before persistence", () => {
  const raw = [
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    "Cookie: sessionid=live-session-value",
    "api_key=live-api-key-value",
    "csrf_token=live-csrf-token sessionid=live-session-id",
    "ghp_123456789012345678901234567890123456",
    "AKIA1234567890ABCDEF",
    "https://example.test/callback?token=live-query-token&next=%2Fhome",
    "eyJabcdefghijk.abcdefghijk.abcdefghijk",
    "-----BEGIN PRIVATE KEY-----private-key-material-----END PRIVATE KEY-----",
  ].join(" ")
  const safe = redactResearchSecrets(raw)
  expect(safe).not.toContain("abcdefghijklmnopqrstuvwxyz")
  expect(safe).not.toContain("live-session-value")
  expect(safe).not.toContain("live-api-key-value")
  expect(safe).not.toContain("live-csrf-token")
  expect(safe).not.toContain("live-session-id")
  expect(safe).not.toContain("ghp_123456789012345678901234567890123456")
  expect(safe).not.toContain("AKIA1234567890ABCDEF")
  expect(safe).not.toContain("live-query-token")
  expect(safe).not.toContain("eyJabcdefghijk.abcdefghijk.abcdefghijk")
  expect(safe).not.toContain("private-key-material")
  expect(safe).toContain("next=%2Fhome")
})


test("research auth-wall detection flags gated content without treating normal reports as login walls", () => {
  expect(looksLikeResearchAuthenticationWall(
    "https://reports.example.test/report/123",
    "Sign in to continue",
    "Please sign in to continue reading this report.",
    "<html><body>Please sign in to continue reading this report.</body></html>",
  )).toBe(true)
  expect(looksLikeResearchAuthenticationWall(
    "https://reports.example.test/report/123",
    "IDOR exposes private API data",
    "The issue allows another user to read a private object when authorization is missing.",
    "<html><body>Public write-up</body></html>",
  )).toBe(false)
})


test("does not mistake a public login-bypass writeup for a login wall", () => {
  expect(looksLikeResearchAuthenticationWall(
    "https://reports.example.test/writeups/login-bypass",
    "Login bypass through weak account recovery",
    "The author demonstrates a public vulnerability report with reproduction and impact details.",
    "<html><body>Public writeup</body></html>",
  )).toBe(false)
})


test("research URL normalization removes embedded credentials and secret query parameters", () => {
  expect(normalizeResearchUrl("https://user:pass@reports.example.test/report?id=42")).toBeUndefined()
  expect(normalizeResearchUrl("https://reports.example.test/report?id=42&token=secret-value&signature=sig-value#section"))
    .toBe("https://reports.example.test/report?id=42")
  expect(normalizeResearchUrl("https://reports.example.test/report?access_token=abc&Page=2"))
    .toBe("https://reports.example.test/report?Page=2")
})


test("learning queue floors non-integer item limits instead of exceeding the requested budget", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const cachedText = [
        "A bug bounty report describes an insecure direct object reference (IDOR) caused by missing object-level authorization.",
        "Prerequisite: use two test-owned accounts and one object owned by the first account.",
        "Reproduction: capture the owner's GET /api/objects/123 request, repeat it with the second controlled account, and compare the response.",
        "Impact: the second account can read a private record without authorization. Confirm the result against the owner baseline.",
        "False-positive caution: an exposed identifier alone does not demonstrate unauthorized access.",
        "Unique fixture marker: " + marker,
      ].join(" ").repeat(4)

      for (const suffix of ["first", "second"]) {
        ResearchQueue.enqueue({
          sourceID: "portswigger",
          sourceURL: "https://portswigger.net/web-security/access-control/idor?limit_test=" + marker + "-" + suffix,
          title: "IDOR limit test " + marker + "-" + suffix,
          payload: { cached_text: cachedText + " " + suffix },
        })
      }

      const result = await learnResearchQueue({ limit: 1.5, sourceID: "portswigger" })
      expect(result.claimed).toBe(1)
      expect(ResearchQueue.stats("portswigger").queued).toBe(1)
      await Instance.dispose()
    },
  })
})

test("learning worker applies one global automatic auth-retry budget across sources", async () => {
  const credentialEnvs = [
    "CYBERSTRIKE_RESEARCH_COOKIE_HACKERONE_HACKTIVITY",
    "CYBERSTRIKE_RESEARCH_COOKIE_INTIGRITI",
  ]
  const originals = new Map(credentialEnvs.map((name) => [name, process.env[name]]))
  for (const name of credentialEnvs) process.env[name] = "session=operator-provided-test-value"

  try {
    await using dir = await tmpdir({ git: true })
    await Instance.provide({
      directory: dir.path,
      fn: async () => {
        const marker = crypto.randomUUID()
        const blockedRows = [
          { sourceID: "hackerone-hacktivity", sourceURL: "https://hackerone.com/hacktivity/archive-" + marker },
          { sourceID: "hackerone-hacktivity", sourceURL: "https://hackerone.com/hacktivity/archive-2-" + marker },
          { sourceID: "intigriti", sourceURL: "https://www.intigriti.com/researchers/blog/archive-" + marker },
          { sourceID: "intigriti", sourceURL: "https://www.intigriti.com/researchers/blog/archive-2-" + marker },
        ]
        const staleUpdatedAt = Date.now() - 11 * 60_000
        for (const row of blockedRows) {
          ResearchQueue.blockAuthentication({
            ...row,
            reason: "HTTP 401",
            payload: { crawl_page: true },
          })
          const saved = ResearchQueue.find(row.sourceID, row.sourceURL)
          if (!saved) throw new Error("expected auth-blocked research row to exist")
          Database.use((db) =>
            db.update(ResearchQueueTable)
              .set({ updated_at: staleUpdatedAt })
              .where(eq(ResearchQueueTable.sequence, saved.sequence))
              .run(),
          )
        }

        const result = await learnResearchQueue({ limit: 1 })
        expect(result.claimed).toBe(0)
        const statuses = blockedRows.map((row) => ResearchQueue.find(row.sourceID, row.sourceURL)?.status)
        expect(statuses.filter((status) => status === "discovered")).toHaveLength(1)
        expect(statuses.filter((status) => status === "blocked_auth")).toHaveLength(3)
        await Instance.dispose()
      },
    })
  } finally {
    for (const [name, original] of originals) {
      if (original === undefined) delete process.env[name]
      else process.env[name] = original
    }
  }
})

test("research queue resumes authenticated work and learns cached report text without a second fetch", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const sourceID = "portswigger"
      // The shared knowledge store may outlive the temporary project database. Keep both
      // URL identity and content fingerprint unique so this test proves a fresh ingestion.
      const marker = crypto.randomUUID()
      const sourceURL = "https://portswigger.net/web-security/access-control/idor?test_id=" + marker
      ResearchQueue.enqueue({
        sourceID,
        sourceURL,
        title: "IDOR report " + marker,
        payload: {
          cached_text: [
            "Insecure direct object reference (IDOR) occurs when an application does not check object-level authorization.",
            "An authenticated user can change the object ID in GET /api/users/123 and read another user's private account data.",
            "Reproduction: use two controlled accounts, capture the owner's request, then repeat it with the second account and compare the response.",
            "Impact: unauthorized access to private records. Verify the result against an owner-account baseline and do not infer a vulnerability from an identifier alone.",
            "Unique test marker: " + marker,
          ].join(" ").repeat(4),
        },
      })

      const originalFetch = globalThis.fetch
      let fetchCalls = 0
      globalThis.fetch = (async () => {
        fetchCalls++
        throw new Error("cached research content must not trigger another HTTP fetch")
      }) as unknown as typeof fetch
      try {
        const result = await learnResearchQueue({ limit: 1, sourceID })
        expect(result.learned).toBe(1)
        expect(fetchCalls).toBe(0)
        expect(ResearchQueue.find(sourceID, sourceURL)?.status).toBe("learned")

        // Keep this coverage in the same Instance scope: Instance/Database are process-wide.
        const authSourceID = "hackerone-hacktivity"
        const cookieEnv = "CYBERSTRIKE_RESEARCH_COOKIE_HACKERONE_HACKTIVITY"
        const authorizationEnv = "CYBERSTRIKE_RESEARCH_AUTHORIZATION_HACKERONE_HACKTIVITY"
        const originalCookie = process.env[cookieEnv]
        const originalAuthorization = process.env[authorizationEnv]
        const intigritiCookieEnv = "CYBERSTRIKE_RESEARCH_COOKIE_INTIGRITI"
        const originalIntigritiCookie = process.env[intigritiCookieEnv]
        const indexURL = "https://hackerone.com/hacktivity"
        const reportURL = "https://hackerone.com/reports/123456"
        const otherURL = "https://portswigger.net/web-security/access-control/idor"
        process.env[cookieEnv] = "session=operator-provided-test-value"
        delete process.env[authorizationEnv]
        try {
          ResearchQueue.blockAuthentication({
            sourceID: authSourceID,
            sourceURL: indexURL,
            reason: "HTTP 401",
            payload: { crawl_page: true },
          })
          ResearchQueue.blockAuthentication({ sourceID: authSourceID, sourceURL: reportURL, reason: "HTTP 401" })
          ResearchQueue.blockAuthentication({ sourceID: "portswigger", sourceURL: otherURL, reason: "HTTP 401" })

          // Automatic retries keep recently blocked work parked until the cooldown expires.
          expect(await retryAuthenticatedResearch({ sourceID: authSourceID, limit: 10 })).toBe(0)

          // An explicit retry-auth action may bypass cooldown, but still requires a configured session.
          const immediateURL = "https://hackerone.com/reports/immediate123"
          ResearchQueue.blockAuthentication({ sourceID: authSourceID, sourceURL: immediateURL, reason: "HTTP 401" })
          // Manual retry is source-scoped, so it requeues all three HackerOne entries.
          expect(await retryAuthenticatedResearch({ sourceID: authSourceID, limit: 10, retryImmediately: true })).toBe(3)
          expect(ResearchQueue.find(authSourceID, indexURL)?.status).toBe("discovered")
          expect(ResearchQueue.find(authSourceID, indexURL)?.payload?.crawl_page).toBe(true)
          expect(ResearchQueue.find(authSourceID, reportURL)?.status).toBe("queued")
          expect(ResearchQueue.find(authSourceID, immediateURL)?.status).toBe("queued")
          // A separate source without configured credentials must remain blocked.
          expect(ResearchQueue.find("portswigger", otherURL)?.status).toBe("blocked_auth")

          // The requested limit is global across authenticated sources, not repeated per source.
          process.env[intigritiCookieEnv] = "session=operator-provided-test-value"
          const budgetRows = [
            { sourceID: authSourceID, sourceURL: "https://hackerone.com/reports/budget-a-" + marker },
            { sourceID: authSourceID, sourceURL: "https://hackerone.com/reports/budget-b-" + marker },
            { sourceID: "intigriti", sourceURL: "https://intigriti.com/reports/budget-a-" + marker },
            { sourceID: "intigriti", sourceURL: "https://intigriti.com/reports/budget-b-" + marker },
          ]
          for (const row of budgetRows) {
            ResearchQueue.blockAuthentication({ ...row, reason: "HTTP 401" })
          }
          expect(await retryAuthenticatedResearch({ limit: 1, retryImmediately: true })).toBe(1)
          const retriedRows = budgetRows.filter((row) =>
            ResearchQueue.find(row.sourceID, row.sourceURL)?.status !== "blocked_auth",
          )
          expect(retriedRows).toHaveLength(1)
        } finally {
          if (originalCookie === undefined) delete process.env[cookieEnv]
          else process.env[cookieEnv] = originalCookie
          if (originalAuthorization === undefined) delete process.env[authorizationEnv]
          else process.env[authorizationEnv] = originalAuthorization
          if (originalIntigritiCookie === undefined) delete process.env[intigritiCookieEnv]
          else process.env[intigritiCookieEnv] = originalIntigritiCookie
        }
      } finally {
        globalThis.fetch = originalFetch
        await Instance.dispose()
      }
    },
  })
})

