import { expect, test } from "bun:test"
import { assessFindingChecks, FINDING_VALIDATION_CHECKS, type FindingValidationInputCheck } from "../../src/methodology/finding-validation"

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
  const result = assessFindingChecks(checks)
  expect(result.verdict).toBe("false_positive")
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
