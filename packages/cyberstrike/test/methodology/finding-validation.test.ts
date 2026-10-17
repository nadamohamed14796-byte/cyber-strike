import { expect, test } from "bun:test"
import { assessFindingChecks, FINDING_VALIDATION_CHECKS, recommendValidationStrategies, type FindingValidationInputCheck } from "../../src/methodology/finding-validation"
import { FindingValidation } from "../../src/methodology/finding-validation"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Vulnerability } from "../../src/session/vulnerability"
import { Database } from "../../src/storage/db"
import { IntelEntryTable } from "../../src/methodology/methodology.sql"
import { TargetMemory } from "../../src/target"
import { tmpdir } from "../fixture/fixture"

function checklist(
  overrides: Partial<Record<FindingValidationInputCheck["id"], Partial<FindingValidationInputCheck>>> = {},
): FindingValidationInputCheck[] {
  return FINDING_VALIDATION_CHECKS.map((definition) => ({
    id: definition.id,
    status: "pass",
    reason: "Verified with a controlled test",
    evidence: "Captured request/response comparison",
    ...overrides[definition.id],
  }))
}


const ATTEMPT_STRATEGIES = [
  "baseline_control", "identity_role", "object_identifier", "http_method", "content_type",
  "session_state", "permission_boundary", "endpoint_variant", "business_logic",
  "cache_waf_environment", "timing_race", "negative_control", "response_comparison", "state_change", "other",
] as const

function makeAttempts(count = 20) {
  return Array.from({ length: count }, (_, index) => ({
    strategy: ATTEMPT_STRATEGIES[index % ATTEMPT_STRATEGIES.length],
    checkID: (["reproducible", "unexpected_behavior", "request_path", "security_impact", "identity_context", "alternative_causes", "control_comparison", "evidence_complete", "benign_behavior_ruled_out", "reviewable"] as const)[index % 10],
    variation: "controlled-variation-" + (index + 1),
    hypothesis: "Test a distinct condition for variation " + (index + 1),
    outcome: index === 0 || index === 1 ? "contradicts" as const : "inconclusive" as const,
    evidence: "Observed controlled response comparison for variation " + (index + 1),
    validConditions: true,
  }))
}

test("requires all ten unique checks", () => {
  const checks = checklist()
  expect(() => assessFindingChecks(checks.slice(0, 9))).toThrow("Exactly 10")
  expect(() => assessFindingChecks([...checks.slice(0, 9), checks[0]])).toThrow("Duplicate")
})

test("classifies as confirmed only when all required checks pass", () => {
  const checks = checklist({ identity_context: { status: "not_applicable", reason: "No identity boundary is claimed" } })
  expect(assessFindingChecks(checks).verdict).toBe("confirmed")
})

test("confirmed validation keeps a finding pending explicit triage", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const session = await Session.create({})
      try {
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "medium",
            title: "Confirmed but untriaged candidate",
            description: "Controlled evidence supports this finding.",
            endpoint: "GET /api/private-record",
          },
        })
        expect(finding.status).toBe("new")
        const result = await FindingValidation.record({
          sessionID: session.id,
          vulnerabilityID: finding.id,
          checks: checklist({ identity_context: { status: "not_applicable", reason: "No identity boundary is claimed" } }),
        })
        expect(result.verdict).toBe("confirmed")
        expect(Vulnerability.get(session.id).find((row) => row.id === finding.id)?.status).toBe("new")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("validation output reports counts and the reason/evidence for all ten checks", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "Replay did not reproduce the claim", evidence: "Two controlled replays matched baseline" },
    request_path: { status: "unknown", reason: "No route-level evidence collected", evidence: "" },
    identity_context: { status: "not_applicable", reason: "No identity boundary is claimed" },
  })
  const result = assessFindingChecks(checks)
  expect(result.output).toContain("Check results: 7 passed, 1 failed, 1 unknown, 1 not applicable (10 total).")
  expect(result.output).toContain("#1 [FAIL]")
  expect(result.output).toContain("Reason: Replay did not reproduce the claim")
  expect(result.output).toContain("Evidence: Two controlled replays matched baseline")
  expect(result.output).toContain("#2 [UNKNOWN]")
  expect(result.output).toContain("#10 [PASS]")
})

test("a missing security header without demonstrated impact cannot be confirmed", () => {
  const checks = checklist({
    security_impact: {
      status: "unknown",
      reason: "Only the missing header was observed; no exploitable browser behavior or sensitive action was demonstrated.",
      evidence: "",
    },
  })
  expect(assessFindingChecks(checks).verdict).toBe("inconclusive")
  expect(assessFindingChecks(checks).unknownCheckIDs).toContain("security_impact")
})

test("invalid-precondition attempts do not count toward false-positive classification", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "Controlled replay did not reproduce the claim", evidence: "Three replays returned the expected owner-bound record" },
    unexpected_behavior: { status: "fail", reason: "Observed response matches intended owner-only behavior", evidence: "Response body and status match the same-account baseline" },
  })
  const invalidAttempts = makeAttempts(20).map((attempt) => ({ ...attempt, validConditions: false }))
  const result = assessFindingChecks(checks, invalidAttempts)
  expect(result.verdict).toBe("inconclusive")
  expect(result.attemptCount).toBe(0)
  expect(result.attemptsRemaining).toBe(20)
  expect(result.output).toContain("0/20 distinct valid evidence-backed attempts")
})

test("unresolved checklist questions block a false-positive verdict even after 20 attempts", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "Controlled replay did not reproduce the claim", evidence: "Twenty distinct valid attempts matched the expected baseline" },
    unexpected_behavior: { status: "fail", reason: "Observed behavior matched intended behavior", evidence: "Controlled comparisons showed no claimed behavior" },
    security_impact: { status: "unknown", reason: "Impact check remains untested", evidence: "" },
  })
  const result = assessFindingChecks(checks, makeAttempts(20))
  expect(result.verdict).toBe("inconclusive")
  expect(result.unknownCheckIDs).toContain("security_impact")
  expect(result.output).toContain("20/20 distinct valid evidence-backed attempts")
})

test("false positive requires multiple evidence-backed contradictions and explains failed numbers", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "Repeated controlled attempts did not reproduce the claim", evidence: "Three replays returned the expected owner-bound record" },
    unexpected_behavior: { status: "fail", reason: "Observed response matches intended owner-only behavior", evidence: "Response body and status match the same-account baseline" },
  })
  expect(assessFindingChecks(checks, makeAttempts(19)).verdict).toBe("inconclusive")
  const result = assessFindingChecks(checks, makeAttempts(20))
  expect(result.verdict).toBe("false_positive")
  expect(result.attemptCount).toBe(20)
  expect(result.attemptsRemaining).toBe(0)
  expect(result.output).toContain("#1")
  expect(result.output).toContain("#3")
})

test("missing failure evidence is rejected and unknown checks remain inconclusive", () => {
  const invalid = checklist({
    reproducible: { status: "fail", reason: "Could not reproduce", evidence: "" },
    unexpected_behavior: { status: "fail", reason: "No abnormal response", evidence: "Response matched baseline" },
  })
  expect(() => assessFindingChecks(invalid)).toThrow("concrete evidence")
  const unknown = checklist({
    reproducible: { status: "unknown", reason: "The test has not been repeated", evidence: "" },
    unexpected_behavior: { status: "unknown", reason: "No controlled response captured", evidence: "" },
  })
  expect(assessFindingChecks(unknown).verdict).toBe("inconclusive")
})

test("one failed check alone does not automatically classify a false positive", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "This attempt did not reproduce the behavior", evidence: "One replay returned normal behavior" },
  })
  expect(assessFindingChecks(checks).verdict).toBe("inconclusive")
})


test("records validation history and removes false positives from confirmed findings", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const session = await Session.create({})
      const finding = Vulnerability.add({
        sessionID: session.id,
        data: {
          severity: "medium",
          title: "Candidate authorization issue",
          description: "Initial finding description.",
          endpoint: "GET /api/orders/123",
          status: "approved",
        },
      })
      const checks = checklist({
        reproducible: {
          status: "fail",
          reason: "Controlled replay did not reproduce unauthorized access.",
          evidence: "Three replays returned the same owner-authorized response.",
        },
        unexpected_behavior: {
          status: "fail",
          reason: "The response matches the expected access-control behavior.",
          evidence: "Owner and non-owner control responses show no unauthorized object data.",
        },
      })

      const invalidAttemptResult = await FindingValidation.record({
        sessionID: session.id,
        vulnerabilityID: finding.id,
        checks,
        attempts: makeAttempts(20).map((attempt) => ({ ...attempt, validConditions: false })),
      })
      expect(invalidAttemptResult.verdict).toBe("inconclusive")
      expect(invalidAttemptResult.attemptCount).toBe(0)

      // Simulate an old finding status written by a version that counted invalid attempts.
      Vulnerability.update({ sessionID: session.id, id: finding.id, status: "false_positive", candidate: null })
      const reopened = await FindingValidation.record({
        sessionID: session.id,
        vulnerabilityID: finding.id,
        checks,
      })
      expect(reopened.verdict).toBe("inconclusive")
      expect(Vulnerability.get(session.id).find((row) => row.id === finding.id)?.status).toBe("new")
      expect(Vulnerability.get(session.id).find((row) => row.id === finding.id)?.candidate).toBe("medium")

      const result = await FindingValidation.record({
        sessionID: session.id,
        vulnerabilityID: finding.id,
        checks,
        attempts: makeAttempts(20),
      })
      const updated = Vulnerability.get(session.id).find((row) => row.id === finding.id)
      const history = FindingValidation.history({ sessionID: session.id, vulnerabilityID: finding.id })

      expect(result.verdict).toBe("false_positive")
      expect(result.output).toContain("#1")
      expect(result.output).toContain("#3")
      expect(updated?.status).toBe("false_positive")
      expect(updated?.description).toContain("[Latest finding validation]")
      expect(Vulnerability.confirmed(session.id).some((row) => row.id === finding.id)).toBe(false)
      expect(history).toHaveLength(3)
      expect(history[0]?.attempt_count).toBe(20)
      expect(history[1]?.attempt_count).toBe(0)
      expect(history[2]?.attempt_count).toBe(0)
      expect(history[0]?.failed_check_ids).toEqual(["reproducible", "unexpected_behavior"])
      await Session.remove(session.id)
    },
  })
})

test("a check cannot pass without evidence, and not-applicable needs a rationale", () => {
  expect(() =>
    assessFindingChecks(checklist({ reproducible: { status: "pass", evidence: "" } })),
  ).toThrow("passed check needs concrete evidence")
  expect(() =>
    assessFindingChecks(checklist({ identity_context: { status: "not_applicable", reason: "" } })),
  ).toThrow("not_applicable check needs a reason")
})

test("persists validation summaries into notes for the uniquely observed target only", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const session = await Session.create({})
      const workspace = await TargetMemory.ensure("https://validation-note.example.test")
      Database.use((db) =>
        db.insert(IntelEntryTable).values({
          id: "intel_validation_note_test",
          session_id: session.id,
          type: "endpoint",
          title: "Observed orders endpoint",
          detail: "Captured during the test session",
          source: "test",
          asset: "https://validation-note.example.test/api/orders/123",
          confidence_level: "high",
          tags: ["api-endpoint", "object-identifier"],
          chain_potential: null,
          related_entries: [],
          status: "new",
          position: 1,
        }).run(),
      )
      const finding = Vulnerability.add({
        sessionID: session.id,
        data: {
          severity: "medium",
          title: "Candidate order authorization issue",
          description: "Initial candidate.",
          endpoint: "GET /api/orders/123",
          status: "approved",
        },
      })
      const result = await FindingValidation.record({
        sessionID: session.id,
        vulnerabilityID: finding.id,
        checks: checklist({
          reproducible: {
            status: "fail",
            reason: "Controlled replay did not reproduce unauthorized access.",
            evidence: "Three replays returned the expected owner-authorized response.",
          },
          unexpected_behavior: {
            status: "fail",
            reason: "The response matched the expected access-control behavior.",
            evidence: "Owner and non-owner control responses contained no unauthorized object data.",
          },
        }),
        attempts: makeAttempts(20),
      })
      expect(result.targetNoteID).toBeTruthy()
      const notes = TargetMemory.allNotes(workspace.id)
      const note = notes.find((item) => item.id === result.targetNoteID)
      expect(note?.title).toContain("Candidate order authorization issue")
      expect(note?.content).toContain("false_positive")
      expect(note?.content).toContain("reproducible, unexpected_behavior")
      expect(note?.content).not.toContain("Three replays returned")
      await Session.remove(session.id)
    },
  })
})


test("does not count duplicate variation keys as additional attempts across assessments", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const session = await Session.create({})
      const finding = Vulnerability.add({
        sessionID: session.id,
        data: { severity: "medium", title: "Candidate", description: "Candidate", endpoint: "GET /api/item", status: "approved" },
      })
      const first = makeAttempts(10)
      const one = await FindingValidation.record({ sessionID: session.id, vulnerabilityID: finding.id, checks: checklist(), attempts: first })
      expect(one.attemptCount).toBe(10)
      const repeated = first.slice(0, 5).map((attempt) => ({ ...attempt, evidence: attempt.evidence + " repeated observation" }))
      const two = await FindingValidation.record({ sessionID: session.id, vulnerabilityID: finding.id, checks: checklist(), attempts: repeated })
      expect(two.attemptCount).toBe(10)
      expect(two.attemptsRemaining).toBe(10)
      expect(two.verdict).not.toBe("false_positive")
      await Session.remove(session.id)
    },
  })
})


test("recommends validation strategies based on finding signals", () => {
  const idor = recommendValidationStrategies("IDOR: cross-account order object authorization bypass")
  expect(idor).toContain("identity_role")
  expect(idor).toContain("object_identifier")
  expect(idor).toContain("permission_boundary")
  const xss = recommendValidationStrategies("Reflected XSS in search parameter")
  expect(xss).toContain("content_type")
  expect(xss).not.toEqual(idor)
})

test("does not allow one variation to count twice under different strategy labels", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "Observed behavior contradicts the claim", evidence: "A controlled response did not reproduce the claimed behavior" },
    unexpected_behavior: { status: "fail", reason: "Response matched the benign baseline", evidence: "The response matched the baseline comparison" },
  })
  const attempts = makeAttempts(20)
  attempts[1] = { ...attempts[1]!, strategy: "other", variation: attempts[0]!.variation }
  expect(() => assessFindingChecks(checks, attempts)).toThrow("Duplicate validation attempt variation")
})


test("accumulates 20 distinct attempts across separate validation calls before false-positive classification", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const session = await Session.create({})
      const finding = Vulnerability.add({
        sessionID: session.id,
        data: { severity: "medium", title: "Candidate authorization finding", description: "Candidate", endpoint: "GET /api/items/{id}", status: "approved" },
      })
      const checks = checklist({
        reproducible: { status: "fail", reason: "Controlled tests did not reproduce the claim", evidence: "Observed response matched the owner-authorized baseline" },
        unexpected_behavior: { status: "fail", reason: "Observed behavior matched intended access control", evidence: "Owner and non-owner control responses exposed no unauthorized data" },
      })
      const first = await FindingValidation.record({
        sessionID: session.id,
        vulnerabilityID: finding.id,
        checks,
        attempts: makeAttempts(10),
      })
      expect(first.verdict).toBe("inconclusive")
      expect(first.attemptCount).toBe(10)
      const nextAttempts = makeAttempts(10).map((attempt, index) => ({
        ...attempt,
        variation: "second-batch-variation-" + (index + 1),
      }))
      const second = await FindingValidation.record({
        sessionID: session.id,
        vulnerabilityID: finding.id,
        checks,
        attempts: nextAttempts,
      })
      expect(second.attemptCount).toBe(20)
      expect(second.verdict).toBe("false_positive")
      await Session.remove(session.id)
    },
  })
})
