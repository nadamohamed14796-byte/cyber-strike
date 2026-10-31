import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Vulnerability } from "../../src/session/vulnerability"
import { VerificationLedger } from "../../src/session/verification-ledger"
import { TargetMemory } from "../../src/target"
import { UpdateFindingEvidenceTool } from "../../src/tool/update-finding-evidence"

function mockCtx(sessionID: string, agent = "impact-hunter"): any {
  return {
    sessionID,
    messageID: undefined,
    agent,
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => undefined,
  }
}

async function makeCandidate(sessionID: string, withPoc = false) {
  await TargetMemory.configureScope("https://evidence-test.example.test", {
    include: ["evidence-test.example.test"],
    authorizationSource: "Impact Hunter PoC evidence fixture",
    authorizationReference: "https://evidence-test.example.test/security",
  })
  const workspace = await TargetMemory.ensure("https://evidence-test.example.test")
  return Vulnerability.add({
    sessionID,
    data: {
      severity: "medium",
      title: "[UNCONFIRMED CANDIDATE] Potential reflected HTML injection in search output",
      description: "A submitted marker appears in the HTML response, but safe encoding or browser execution has not yet been resolved.",
      candidate: "medium",
      endpoint: "GET https://evidence-test.example.test/api/search",
      target_id: workspace.id,
      file: "javascript/assets/search.js",
      line_start: 184,
      line_end: 202,
      ...(withPoc ? { poc: "Existing proof with a complete baseline and controlled result; this should not be overwritten." } : {}),
    },
  })
}

function recordConfirmedProof(sessionID: string, finding: Vulnerability.Info, slug: string) {
  const hypothesisKey = "finding:" + finding.id + ":poc:" + slug
  const evidenceRef = "test-evidence://impact-hunter/" + finding.id + "/" + slug
  VerificationLedger.record({
    sessionID,
    hypothesisKey,
    asset: "https://evidence-test.example.test",
    endpoint: finding.endpoint,
    vulnerabilityClass: "xss",
    attempt: {
      strategyID: "xss-context-proof-" + slug,
      variantKey: "controlled-output-context-" + slug,
      rationale: "Distinguish the observed output context using a minimal controlled marker and a negative control",
      resultSummary: "Observed the controlled browser-side proof under valid test conditions",
      evidenceRef,
      validConditions: true,
    },
    decisiveResult: "confirmed",
  })
  return { hypothesisKey, evidenceRef }
}

test("Impact Hunter persists a verified PoC onto the same candidate without approving or raising it", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const finding = await makeCandidate(session.id)
        const baselineNotes = "The captured response contains the submitted marker as encoded HTML text; no executable payload or browser-side trigger has been demonstrated."
        expect(Vulnerability.update({
          sessionID: session.id,
          id: finding.id,
          poc: baselineNotes,
          candidate: "high",
          expectedStatus: "new",
        })).toBe(true)
        const proof = recordConfirmedProof(session.id, finding, "attribute-context")
        const tool = await UpdateFindingEvidenceTool.init()
        const result = await tool.execute({
          id: finding.id,
          proof_hypothesis_key: proof.hypothesisKey,
          poc: [
            "Prerequisite: use the two researcher-controlled test accounts and the captured search request.",
            "Baseline request: send the original query with the inert marker and preserve its response.",
            "Proof request: place the same marker in the independently observed attribute context and verify the controlled browser sink.",
            "Expected: the value remains inert. Actual: the authorized test browser reports the controlled canary execution.",
            "Diff: the attribute context reaches the observed sink while the negative-control context remains encoded.",
          ].join("\n"),
          steps_to_reproduce: "1. Sign in using the researcher-owned test account. 2. Send the captured search request with the inert marker. 3. Observe the controlled sink and compare the negative control.",
          demonstrated_impact: "The controlled marker executes in the researcher's own test browser in the observed attribute context; no other user or data was accessed.",
          evidence_refs: [proof.evidenceRef],
          description_addendum: "The source-to-sink path is tied to the captured search request and the inspected output-context function.",
          recommendation: "Apply context-aware output encoding at the final HTML attribute sink and add a regression test for this context.",
          source_file: "javascript/assets/search.js",
          source_line_start: 184,
          source_line_end: 202,
        }, mockCtx(session.id))

        expect((result.metadata as any).updated).toBe(true)
        expect((result.metadata as any).poc_saved).toBe(true)
        const saved = Vulnerability.get(session.id).find((row) => row.id === finding.id)
        expect(saved?.id).toBe(finding.id)
        expect(saved?.status).toBe("new")
        expect(saved?.severity).toBe("high")
        expect(saved?.candidate ?? null).toBeNull()
        expect(saved?.title).not.toContain("[UNCONFIRMED CANDIDATE]")
        expect(saved?.poc).toContain("Prior candidate evidence / unverified baseline notes")
        expect(saved?.poc).toContain(baselineNotes)
        expect(saved?.poc).toContain("Proof request:")
        expect(saved?.steps_to_reproduce).toContain("researcher-owned test account")
        expect(saved?.business_impact).toContain("controlled marker executes")
        expect(saved?.file).toBe("javascript/assets/search.js")
        expect(saved?.line_start).toBe(184)
        expect(saved?.line_end).toBe(202)
        expect(saved?.description).toContain("[Impact Hunter — PoC gap closed; pending full validation]")
        expect(result.output).toContain("remains NEW / unapproved")
        expect(result.output).toContain("claimed severity restored provisionally")
        expect(result.output).toContain("all ten validate_finding checks")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("PoC evidence update rejects references not present in the durable proof ledger", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const finding = await makeCandidate(session.id)
        const proof = recordConfirmedProof(session.id, finding, "dom-source-sink")
        const tool = await UpdateFindingEvidenceTool.init()
        const result = await tool.execute({
          id: finding.id,
          proof_hypothesis_key: proof.hypothesisKey,
          poc: "A detailed but deliberately unaccepted test proof. Baseline, changed request, expected behavior, observed behavior, and response diff are included here.",
          steps_to_reproduce: "1. Use the controlled test account. 2. Submit the captured request with the inert canary. 3. Compare the observed response against the negative control.",
          demonstrated_impact: "The supplied evidence reference is invalid, so no demonstrated security impact may be attached to this record.",
          evidence_refs: ["test-evidence://invented/not-in-ledger"],
        }, mockCtx(session.id))
        expect((result.metadata as any).updated).toBe(false)
        expect((result.metadata as any).reason).toBe("evidence_reference_mismatch")
        const saved = Vulnerability.get(session.id).find((row) => row.id === finding.id)
        expect(saved?.poc).toBeUndefined()
        expect(saved?.status).toBe("new")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("PoC evidence update is restricted to Impact Hunter and cannot overwrite an existing PoC", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const pending = await makeCandidate(session.id)
        const tool = await UpdateFindingEvidenceTool.init()
        const nonHunter = await tool.execute({
          id: pending.id,
          proof_hypothesis_key: "finding:" + pending.id + ":poc:untrusted",
          poc: "A detailed proof string that is not accepted because the caller is not the Impact Hunter and must not update the candidate.",
          steps_to_reproduce: "1. Use the controlled test account. 2. Send the observed request. 3. Compare the result with the negative control.",
          demonstrated_impact: "This statement is not accepted because the calling agent is not the designated proof-gap investigator.",
          evidence_refs: ["test-evidence://not-used"],
        }, mockCtx(session.id, "cyberstrike"))
        expect((nonHunter.metadata as any).reason).toBe("impact_hunter_only")

        const existing = await makeCandidate(session.id, true)
        const proof = recordConfirmedProof(session.id, existing, "already-has-proof")
        const hunter = await tool.execute({
          id: existing.id,
          proof_hypothesis_key: proof.hypothesisKey,
          poc: "A second proof must not overwrite the original existing PoC; use validation instead of replacing the evidence.",
          steps_to_reproduce: "1. Use the controlled test account. 2. Send the observed request. 3. Compare the result with the negative control.",
          demonstrated_impact: "An existing PoC should be preserved and is not eligible for a proof-gap update.",
          evidence_refs: [proof.evidenceRef],
        }, mockCtx(session.id))
        expect((hunter.metadata as any).reason).toBe("poc_already_present")
        expect(Vulnerability.get(session.id).find((row) => row.id === existing.id)?.poc).toContain("Existing proof")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})
