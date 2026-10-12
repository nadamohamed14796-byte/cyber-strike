import { expect, test } from "bun:test"
import { assessFindingChecks, FINDING_VALIDATION_CHECKS, type FindingValidationInputCheck } from "../../src/methodology/finding-validation"
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
    variation: "controlled-variation-" + (index + 1),
    hypothesis: "Test a distinct condition for variation " + (index + 1),
    outcome: index < 2 ? "contradicts" as const : "inconclusive" as const,
    evidence: "Observed controlled response comparison for variation " + (index + 1),
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
      expect(history).toHaveLength(1)
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
