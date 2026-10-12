import { expect, test } from "bun:test"
import { extractResearchDetails, looksLikeResearchAuthenticationWall, normalizeResearchUrl, redactResearchSecrets } from "../../src/research/ingest"

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
