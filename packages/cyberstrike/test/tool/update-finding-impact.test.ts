import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Vulnerability } from "../../src/session/vulnerability"
import { VerificationLedger } from "../../src/session/verification-ledger"
import { FindingValidation, FINDING_VALIDATION_CHECKS } from "../../src/methodology/finding-validation"
import { UpdateFindingImpactTool } from "../../src/tool/update-finding-impact"

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

async function makeApprovedConfirmedFinding(sessionID: string) {
  const finding = Vulnerability.add({
    sessionID,
    data: {
      severity: "low",
      title: "Controlled authorization boundary",
      description: "A reproducible authorization weakness with a limited demonstrated effect.",
      endpoint: "GET https://impact-test.example.test/api/profile/fixture",
    },
  })
  const evidenceRef = "test-evidence://impact-hunter/" + finding.id + "/confirmed-escalation"
  VerificationLedger.record({
    sessionID,
    hypothesisKey: "finding:" + finding.id,
    asset: "https://impact-test.example.test",
    endpoint: finding.endpoint,
    vulnerabilityClass: "authorization",
    attempt: {
      strategyID: "controlled-impact-replay",
      variantKey: "controlled-cross-role-proof",
      rationale: "Verify the additional impact with a controlled role and owned fixture",
      resultSummary: "Observed the additional authorized-boundary violation against the negative control",
      evidenceRef,
      validConditions: true,
    },
    decisiveResult: "confirmed",
  })
  const validation = await FindingValidation.record({
    sessionID,
    vulnerabilityID: finding.id,
    checks: FINDING_VALIDATION_CHECKS.map((check) => ({
      id: check.id,
      status: "pass" as const,
      reason: "Executed with valid scope, controlled identity and a reproducible result",
      evidence: "Captured controlled baseline and test evidence for " + check.id,
    })),
  })
  expect(validation.verdict).toBe("confirmed")
  expect(Vulnerability.update({
    sessionID,
    id: finding.id,
    status: "approved",
    expectedStatus: "new",
  })).toBe(true)
  return { finding, baselineValidationID: validation.id }
}

async function recordImpactProof(sessionID: string, finding: Vulnerability.Info, slug: string) {
  const hypothesisKey = "finding:" + finding.id + ":impact:" + slug
  const evidenceRef = "test-evidence://impact-hunter/" + finding.id + "/" + slug
  VerificationLedger.record({
    sessionID,
    hypothesisKey,
    asset: "https://impact-test.example.test",
    endpoint: finding.endpoint,
    vulnerabilityClass: "authorization",
    attempt: {
      strategyID: "impact-escalation-" + slug,
      variantKey: "controlled-impact-proof-" + slug,
      rationale: "Test one new impact-escalation hypothesis after the initial approval baseline",
      resultSummary: "Observed a new security-boundary impact under controlled conditions",
      evidenceRef,
      validConditions: true,
    },
    decisiveResult: "confirmed",
  })
  const validation = await FindingValidation.record({
    sessionID,
    vulnerabilityID: finding.id!,
    checks: FINDING_VALIDATION_CHECKS.map((check) => ({
      id: check.id,
      status: "pass" as const,
      reason: "Rechecked after the additional impact hypothesis was executed",
      evidence: "Captured post-handoff evidence for " + check.id,
    })),
  })
  expect(validation.verdict).toBe("confirmed")
  return { hypothesisKey, evidenceRef }
}

test("only Impact Hunter can update an approved finding after confirmed ten-check validation", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const { finding, baselineValidationID } = await makeApprovedConfirmedFinding(session.id)
        const impactProof = await recordImpactProof(session.id, finding, "cross-account-read")
        const tool = await UpdateFindingImpactTool.init()
        const result = await tool.execute({
          id: finding.id,
          severity: "medium",
          demonstratedImpact: "The controlled cross-role replay exposed an additional private profile field belonging to the second tester-owned account.",
          severityRationale: "The issue crosses a user-to-user confidentiality boundary with a reproducible read of non-public account data, while remaining limited to the controlled account fixture.",
          baseline_validation_id: baselineValidationID,
          impact_hypothesis_key: impactProof.hypothesisKey,
          evidence_refs: [impactProof.evidenceRef],
        }, mockCtx(session.id))
        expect((result.metadata as any).updated).toBe(true)
        const saved = Vulnerability.get(session.id).find((row) => row.id === finding.id)
        expect(saved?.severity).toBe("medium")
        expect(saved?.status).toBe("approved")
        expect(saved?.description).toContain("[Impact Hunter — evidence-backed impact escalation]")
        expect(saved?.description).toContain(impactProof.evidenceRef)

        const laterValidation = await FindingValidation.record({
          sessionID: session.id,
          vulnerabilityID: finding.id,
          checks: FINDING_VALIDATION_CHECKS.map((check) => ({
            id: check.id,
            status: "pass" as const,
            reason: "Rechecked after impact escalation persistence",
            evidence: "Repeated the controlled evidence review for " + check.id,
          })),
        })
        expect(laterValidation.verdict).toBe("confirmed")
        const afterRevalidation = Vulnerability.get(session.id).find((row) => row.id === finding.id)
        expect(afterRevalidation?.description).toContain(impactProof.evidenceRef)
        expect(afterRevalidation?.description).toContain("[Latest finding validation]")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("Impact Hunter severity update rejects a caller-supplied evidence ref absent from the durable ledger", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const { finding, baselineValidationID } = await makeApprovedConfirmedFinding(session.id)
        const impactProof = await recordImpactProof(session.id, finding, "cross-account-metadata")
        const tool = await UpdateFindingImpactTool.init()
        const result = await tool.execute({
          id: finding.id,
          severity: "high",
          demonstratedImpact: "The additional controlled test demonstrates a meaningful privilege-boundary violation affecting a separate test identity.",
          severityRationale: "A reproducible privilege-boundary crossing supports a higher severity under the program's impact rubric, subject to the controlled scope and account prerequisites.",
          baseline_validation_id: baselineValidationID,
          impact_hypothesis_key: impactProof.hypothesisKey,
          evidence_refs: ["made-up-evidence://not-in-ledger"],
        }, mockCtx(session.id))
        expect((result.metadata as any).updated).toBe(false)
        expect((result.metadata as any).reason).toBe("evidence_reference_mismatch")
        expect(Vulnerability.get(session.id).find((row) => row.id === finding.id)?.severity).toBe("low")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("Impact Hunter severity update rejects non-approved findings and non-Hunter callers", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "low",
            title: "Unapproved candidate",
            description: "This record has not passed validation or triage.",
            endpoint: "GET https://impact-test.example.test/api/pending",
          },
        })
        const tool = await UpdateFindingImpactTool.init()
        const args = {
          id: finding.id,
          severity: "medium" as const,
          demonstratedImpact: "A stronger impact was claimed in the test input but has not been verified for this candidate.",
          severityRationale: "No accepted rationale can be applied because the candidate has not passed the validation and triage workflow.",
          baseline_validation_id: "not-used",
          impact_hypothesis_key: "finding:" + finding.id + ":impact:untrusted",
          evidence_refs: ["test-evidence://not-used"],
        }
        const unapproved = await tool.execute(args, mockCtx(session.id))
        expect((unapproved.metadata as any).reason).toBe("finding_not_approved")

        const nonHunterFinding = await makeApprovedConfirmedFinding(session.id)
        const nonHunter = await tool.execute({
          ...args,
          id: nonHunterFinding.finding.id,
          baseline_validation_id: nonHunterFinding.baselineValidationID,
          impact_hypothesis_key: "finding:" + nonHunterFinding.finding.id + ":impact:untrusted",
          evidence_refs: ["test-evidence://not-used"],
        }, mockCtx(session.id, "cyberstrike"))
        expect((nonHunter.metadata as any).reason).toBe("impact_hunter_only")
        expect(Vulnerability.get(session.id).find((row) => row.id === nonHunterFinding.finding.id)?.severity).toBe("low")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("Impact Hunter cannot lower or repeat the current severity through the escalation tool", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        const { finding, baselineValidationID } = await makeApprovedConfirmedFinding(session.id)
        const tool = await UpdateFindingImpactTool.init()
        const result = await tool.execute({
          id: finding.id,
          severity: "low",
          demonstratedImpact: "The new test evidence is deliberately insufficient to justify a higher severity classification for this record.",
          severityRationale: "No higher impact has been demonstrated beyond the currently accepted low-severity confidentiality boundary.",
          baseline_validation_id: baselineValidationID,
          impact_hypothesis_key: "finding:" + finding.id + ":impact:cross-account-read",
          evidence_refs: ["not-reached-before-severity-check"],
        }, mockCtx(session.id))
        expect((result.metadata as any).reason).toBe("severity_not_higher")
        expect(Vulnerability.get(session.id).find((row) => row.id === finding.id)?.severity).toBe("low")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})
