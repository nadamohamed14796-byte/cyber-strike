import { expect, test } from "bun:test"
import { eq } from "drizzle-orm"
import { Database } from "../../src/storage/db"
import { ResearchQueueTable } from "../../src/research/queue.sql"
import { classifyResearchTopic, extractResearchDetails, learnResearchQueue, looksLikeResearchAuthenticationWall, normalizeResearchUrl, redactResearchSecrets, retryAuthBlockedWithBudget, retryAuthenticatedResearch } from "../../src/research/ingest"
import { RESEARCH_SOURCES } from "../../src/research/sources"
import { ReportKnowledge } from "../../src/learning/report-knowledge"
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
  const slackTokenFixture = "xoxb-test-" + crypto.randomUUID().replace(/-/g, "")
  const gitlabTokenFixture = "glpat-" + crypto.randomUUID().replace(/-/g, "").repeat(2)
  const raw = [
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    "Cookie: sessionid=live-session-value",
    "api_key=live-api-key-value",
    "csrf_token=live-csrf-token sessionid=live-session-id",
    "ghp_123456789012345678901234567890123456",
    "AKIA1234567890ABCDEF",
    "ASIA1234567890ABCDEF",
    "AWS_SECRET_ACCESS_KEY=aws-secret-key-value",
    slackTokenFixture,
    gitlabTokenFixture,
    "https://example.test/callback?token=live-query-token&next=%2Fhome",
    "https://example.test/download?X-Amz-Signature=live-signed-value&AWS_SECRET_ACCESS_KEY=live-aws-url-secret&client_secret=live-client-secret&next=%2Fhome",
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
  expect(safe).not.toContain("ASIA1234567890ABCDEF")
  expect(safe).not.toContain("aws-secret-key-value")
  expect(safe).not.toContain(slackTokenFixture)
  expect(safe).not.toContain(gitlabTokenFixture)
  expect(safe).not.toContain("live-query-token")
  expect(safe).not.toContain("live-signed-value")
  expect(safe).not.toContain("live-aws-url-secret")
  expect(safe).not.toContain("live-client-secret")
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

test("research URL normalization strips provider-specific signed and secret query keys", () => {
  expect(
    normalizeResearchUrl(
      "https://reports.example.test/download?X-Amz-Signature=signed-value&AWS_SECRET_ACCESS_KEY=secret-value&client_secret=client-value&Page=2",
    ),
  ).toBe("https://reports.example.test/download?Page=2")
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

test("authenticated research retries enforce one global budget across configured sources", () => {
  const sources = [
    { id: "hackerone-hacktivity", hasCredentials: true },
    { id: "intigriti", hasCredentials: true },
    { id: "portswigger", hasCredentials: false },
  ]
  const calls: Array<{ limit: number; sourceID: string; minAgeMs: number }> = []
  const retry = (limit: number, sourceID: string, minAgeMs: number) => {
    calls.push({ limit, sourceID, minAgeMs })
    return 1
  }

  const total = retryAuthBlockedWithBudget(
    sources,
    1,
    (source) => source.hasCredentials,
    retry,
    10 * 60_000,
  )

  expect(total).toBe(1)
  expect(calls).toEqual([
    { limit: 1, sourceID: "hackerone-hacktivity", minAgeMs: 10 * 60_000 },
  ])
})

test("authenticated research retry budget continues when an eligible source has nothing to retry", () => {
  const sources = [
    { id: "source-empty", hasCredentials: true },
    { id: "source-with-work", hasCredentials: true },
  ]
  const calls: Array<{ limit: number; sourceID: string }> = []
  const total = retryAuthBlockedWithBudget(
    sources,
    1,
    (source) => source.hasCredentials,
    (limit, sourceID) => {
      calls.push({ limit, sourceID })
      return sourceID === "source-with-work" ? 1 : 0
    },
    10 * 60_000,
  )

  expect(total).toBe(1)
  expect(calls).toEqual([
    { limit: 1, sourceID: "source-empty" },
    { limit: 1, sourceID: "source-with-work" },
  ])
})
test("research queue resumes authenticated work and learns cached report text without a second fetch", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      // Use a unique temporary source ID so claimNext cannot consume older queued
      // PortSwigger work from the shared database instead of the row this test inserted.
      const marker = crypto.randomUUID()
      const sourceID = "portswigger-test-" + marker
      const academySource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!academySource) throw new Error("PortSwigger test source is not configured")
      const isolatedSource = { ...academySource, id: sourceID }
      RESEARCH_SOURCES.push(isolatedSource)
      // The shared knowledge store may outlive the temporary project database. Keep both
      // URL identity and content fingerprint unique so this test proves a fresh ingestion.
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
        const sourceIndex = RESEARCH_SOURCES.indexOf(isolatedSource)
        if (sourceIndex >= 0) RESEARCH_SOURCES.splice(sourceIndex, 1)
        await Instance.dispose()
      }
    },
  })
})



test("research topic classification covers CORS, information disclosure, privilege escalation, misconfiguration, and account takeover", () => {
  expect(classifyResearchTopic("CORS policy exposes a private API", "A report about CORS.")).toBe("cors")
  expect(classifyResearchTopic("Information disclosure through debug logs", "Sensitive values appear in application logs.")).toBe("information-disclosure")
  expect(classifyResearchTopic("Privilege escalation through role assignment", "A role check is missing.")).toBe("privilege-escalation")
  expect(classifyResearchTopic("Security misconfiguration exposes an admin panel", "The application has an insecure configuration.")).toBe("security-misconfiguration")
  expect(classifyResearchTopic("Account takeover through password recovery", "An account can be compromised.")).toBe("account-takeover")
  // Compound titles follow the named topic order, not the source-code regex list order.
  expect(classifyResearchTopic("CORS misconfiguration leads to information disclosure", "A cross-origin policy issue.")).toBe("cors")
  expect(classifyResearchTopic("Security misconfiguration causes privilege escalation", "Privilege changes were possible.")).toBe("security-misconfiguration")
})


test("learning preserves the full source fingerprint when only a cached excerpt is available", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sourceID = "portswigger-fingerprint-" + marker
      const baseSource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!baseSource) throw new Error("PortSwigger test source is not configured")
      const isolatedSource = { ...baseSource, id: sourceID }
      RESEARCH_SOURCES.push(isolatedSource)
      const sourceURL = "https://portswigger.net/web-security/access-control/idor?fingerprint_test=" + marker
      const fullSourceFingerprint = "f".repeat(40)
      const excerpt = [
        "Insecure direct object reference (IDOR) occurs when object-level authorization is missing.",
        "Prerequisite: use two controlled accounts with different object ownership.",
        "Reproduction: capture the owner's GET /api/objects/123 request and repeat it with the second account.",
        "Impact: the second account may read a private record. Compare the response with the owner baseline.",
        "Unique fixture marker: " + marker,
      ].join(" ")

      try {
        ResearchQueue.enqueue({
          sourceID,
          sourceURL,
          title: "IDOR truncated-source fingerprint " + marker,
          payload: {
            cached_text: excerpt,
            cached_text_truncated: true,
            content_length: 150_000,
            content_fingerprint: fullSourceFingerprint,
            source_name: isolatedSource.name,
            source_kind: isolatedSource.kind,
            source_trust: isolatedSource.trust,
          },
        })

        const result = await learnResearchQueue({ limit: 1, sourceID })
        expect(result.learned).toBe(1)

        const row = ReportKnowledge.search({
          query: "IDOR truncated-source fingerprint " + marker,
          sourceKind: "external_report",
          limit: 5,
        }).find((candidate) => candidate.title.includes(marker))
        expect(row).toBeDefined()
        expect(row?.metadata?.content_fingerprint).toBe(fullSourceFingerprint)
        expect(row?.metadata?.content_length).toBe(150_000)
        expect(row?.metadata?.content_truncated_for_learning).toBe(true)
      } finally {
        const sourceIndex = RESEARCH_SOURCES.indexOf(isolatedSource)
        if (sourceIndex >= 0) RESEARCH_SOURCES.splice(sourceIndex, 1)
        await Instance.dispose()
      }
    },
  })
})


test("research extraction keeps explicit CWE identifiers and does not infer severity from incidental adjectives", () => {
  const labelled = extractResearchDetails(
    "CWE-639: IDOR in an object endpoint",
    [
      "Severity: High",
      "CVSS v3.1: 8.2",
      "An authenticated user can access another user's object when object-level authorization is missing.",
      "Reproduction: compare the owner request with a second controlled account.",
    ].join("\n"),
    "idor",
  )
  expect(labelled.cweID).toBe("CWE-639")
  expect(labelled.severity).toBe("high")
  expect(labelled.retrievalSignals).toContain("CWE-639")

  const incidental = extractResearchDetails(
    "High-level overview of low-level API behavior",
    "This writeup describes a medium-sized endpoint and does not state a severity rating.",
  )
  expect(incidental.severity).toBe("unknown")
})
