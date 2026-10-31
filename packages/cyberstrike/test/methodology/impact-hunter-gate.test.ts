import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { Vulnerability } from "../../src/session/vulnerability"
import { TargetMemory } from "../../src/target"
import { evaluateImpactHunterGate } from "../../src/methodology/impact-hunter-gate"

async function makeScopedCandidate(sessionID: string) {
  await TargetMemory.configureScope("https://example.com", {
    include: ["example.com", "*.example.com"],
    exclude: ["admin.example.com"],
    authorizationSource: "Impact Hunter gate fixture",
    authorizationReference: "https://example.com/security",
  })
  const workspace = await TargetMemory.ensure("https://example.com")
  const request = Request.add({
    sessionID,
    method: "GET",
    normalizedPath: "/api/search",
    rawRequest: "GET /api/search?q=owned-fixture HTTP/1.1\\r\\nHost: example.com",
    scheme: "https",
    host: "example.com",
    origin: "https://example.com",
  })
  const finding = Vulnerability.add({
    sessionID,
    data: {
      severity: "medium",
      title: "Potential reflected HTML injection in search output",
      description: "The captured response shows the submitted marker in HTML; a reproducible execution PoC has not been established.",
      endpoint: "GET https://example.com/api/search",
      target_id: workspace.id,
    },
  })
  return { finding, request, workspace }
}

test("proof-gap gate admits a NEW no-PoC candidate only with scoped target and matching captured request evidence", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const { finding, request } = await makeScopedCandidate(session.id)
        const result = evaluateImpactHunterGate({
          finding,
          sessionID: session.id,
          mode: "proof_gap",
        })
        expect(result.allowed).toBe(true)
        expect(result.mode).toBe("proof_gap")
        expect(result.requestIDs).toContain(request?.id)
        expect(result.baselineValidationID).toBeUndefined()
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("proof-gap gate rejects a candidate without a request or source file/line evidence anchor", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        await TargetMemory.configureScope("https://example.com", {
          include: ["example.com"],
          authorizationSource: "Impact Hunter gate fixture",
          authorizationReference: "https://example.com/security",
        })
        const workspace = await TargetMemory.ensure("https://example.com")
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "low",
            title: "Unanchored HTML reflection lead",
            description: "A possible reflection was mentioned, but there is no captured request or verified source location.",
            endpoint: "GET https://example.com/api/not-captured",
            target_id: workspace.id,
          },
        })
        const result = evaluateImpactHunterGate({
          finding,
          sessionID: session.id,
          mode: "proof_gap",
        })
        expect(result.allowed).toBe(false)
        expect(result.reason).toContain("no matching captured request or source file/line")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("proof-gap gate admits a verified source-file anchor without a captured request", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        await TargetMemory.configureScope("https://example.com", {
          include: ["example.com"],
          authorizationSource: "Impact Hunter gate fixture",
          authorizationReference: "https://example.com/security",
        })
        const workspace = await TargetMemory.ensure("https://example.com")
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "medium",
            title: "DOM XSS source-to-sink lead",
            description: "An analyzed source file contains a candidate DOM sink at a concrete caller location, but no execution PoC has been obtained.",
            endpoint: "GET https://example.com/search",
            target_id: workspace.id,
            file: "javascript/assets/search.js",
            line_start: 184,
            line_end: 202,
          },
        })
        const result = evaluateImpactHunterGate({
          finding,
          sessionID: session.id,
          mode: "proof_gap",
        })
        expect(result.allowed).toBe(true)
        expect(result.requestIDs).toHaveLength(0)
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("proof-gap gate rejects PoC-bearing or non-NEW records", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const { finding } = await makeScopedCandidate(session.id)
        expect(Vulnerability.update({
          sessionID: session.id,
          id: finding.id,
          poc: "Existing reproducible proof from a prior controlled test; this record no longer has a proof gap.",
          expectedStatus: "new",
        })).toBe(true)
        const withPoC = Vulnerability.get(session.id).find((row) => row.id === finding.id)!
        const poCResult = evaluateImpactHunterGate({
          finding: withPoC,
          sessionID: session.id,
          mode: "proof_gap",
        })
        expect(poCResult.allowed).toBe(false)
        expect(poCResult.reason).toContain("already contains a PoC")

        expect(Vulnerability.update({
          sessionID: session.id,
          id: finding.id,
          status: "approved",
          expectedStatus: "new",
        })).toBe(true)
        const approved = Vulnerability.get(session.id).find((row) => row.id === finding.id)!
        const statusResult = evaluateImpactHunterGate({
          finding: approved,
          sessionID: session.id,
          mode: "proof_gap",
        })
        expect(statusResult.allowed).toBe(false)
        expect(statusResult.reason).toContain("NEW")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})


test("execution-unconfirmed candidates can enter proof-gap mode even when poc contains only baseline or encoded-reflection notes", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const { finding, request } = await makeScopedCandidate(session.id)
        const baselineNotes = "Captured HTML response contains the marker but encodes it as text; no executable payload or browser trigger has been demonstrated."
        expect(Vulnerability.update({
          sessionID: session.id,
          id: finding.id,
          poc: baselineNotes,
          candidate: "high",
          expectedStatus: "new",
        })).toBe(true)
        const saved = Vulnerability.get(session.id).find((row) => row.id === finding.id)!
        const result = evaluateImpactHunterGate({
          finding: saved,
          sessionID: session.id,
          mode: "proof_gap",
          preferredRequestIDs: request?.id ? [request.id] : [],
        })
        expect(result.allowed).toBe(true)
        expect(result.requestIDs).toContain(request?.id)
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})
