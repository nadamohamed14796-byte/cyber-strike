import { and, desc, eq } from "../storage/db"
import { Database } from "../storage/db"
import { Identifier } from "../id/id"
import { Session } from "../session"
import { Vulnerability } from "../session/vulnerability"
import { TargetMemory } from "../target"
import { FalsePositiveKnowledge } from "./false-positive-knowledge"
import {
  FindingValidationTable,
  type FindingValidationCheckRecord,
  type FindingValidationStatus,
  type FindingValidationVerdict,
  type FindingValidationAttemptRecord,
  type FindingValidationAttemptStrategy,
} from "./finding-validation.sql"

export const FINDING_VALIDATION_CHECKS = [
  { number: 1, id: "reproducible", question: "Can another tester reproduce the behavior reliably with documented steps?" },
  { number: 2, id: "request_path", question: "Does the request demonstrably reach the intended endpoint and code path?" },
  { number: 3, id: "unexpected_behavior", question: "Is there concrete evidence of behavior different from expected or secure behavior?" },
  { number: 4, id: "security_impact", question: "Is there a clear security impact beyond unusual behavior or harmless information?" },
  { number: 5, id: "identity_context", question: "Were roles, sessions, account ownership, permissions, and test data verified for this claim?" },
  { number: 6, id: "alternative_causes", question: "Have cache, CDN/WAF, environment, race conditions, stale state, and tool artifacts been reasonably excluded?" },
  { number: 7, id: "control_comparison", question: "Was there a baseline or control comparison that separates vulnerable behavior from expected behavior?" },
  { number: 8, id: "evidence_complete", question: "Is the evidence attributable, reproducible, minimal, and sufficient for independent review?" },
  { number: 9, id: "benign_behavior_ruled_out", question: "Does controlled evidence rule out an intended or benign explanation? Mark fail only when evidence demonstrates a benign/intended explanation; use unknown if this has not been tested." },
  { number: 10, id: "reviewable", question: "Are the finding, limitations, and reproduction steps documented so another reviewer can verify them?" },
] as const

export type FindingValidationCheckID = (typeof FINDING_VALIDATION_CHECKS)[number]["id"]

export interface FindingValidationAttemptInput extends FindingValidationAttemptRecord {}

export const FINDING_VALIDATION_MIN_ATTEMPTS = 20

export function recommendValidationStrategies(context: string): FindingValidationAttemptStrategy[] {
  const value = context.toLowerCase()
  const common: FindingValidationAttemptStrategy[] = ["baseline_control", "negative_control", "response_comparison", "endpoint_variant"]
  if (/(idor|bola|object.?level|object.?authorization|broken access control|authorization|privilege|tenant|cross.?account|access control)/.test(value)) {
    return ["identity_role", "object_identifier", "permission_boundary", "baseline_control", "negative_control", "response_comparison", "state_change", "session_state", "endpoint_variant", "business_logic"]
  }
  if (/(xss|cross.?site scripting|html injection|script injection|dom.?based)/.test(value)) {
    return ["business_logic", "content_type", "endpoint_variant", "baseline_control", "negative_control", "response_comparison", "session_state", "permission_boundary", "other"]
  }
  if (/(ssrf|server.?side request forgery|url fetch|webhook|url import)/.test(value)) {
    return ["endpoint_variant", "permission_boundary", "negative_control", "response_comparison", "business_logic", "cache_waf_environment", "baseline_control", "other"]
  }
  if (/(sql.?injection|sqli|command injection|template injection|injection)/.test(value)) {
    return ["baseline_control", "negative_control", "content_type", "http_method", "response_comparison", "business_logic", "endpoint_variant", "cache_waf_environment", "other"]
  }
  if (/(csrf|cross.?site request forgery)/.test(value)) {
    return ["session_state", "identity_role", "state_change", "negative_control", "baseline_control", "response_comparison", "content_type", "permission_boundary"]
  }
  if (/(cors|cross.?origin|origin policy)/.test(value)) {
    return ["endpoint_variant", "negative_control", "response_comparison", "permission_boundary", "session_state", "baseline_control", "other"]
  }
  if (/(open redirect|redirect|oauth|callback|ss.?open)/.test(value)) {
    return ["endpoint_variant", "negative_control", "response_comparison", "permission_boundary", "session_state", "baseline_control", "other"]
  }
  if (/(race condition|race.?condition|concurrency|double.?spend|duplicate transaction)/.test(value)) {
    return ["timing_race", "state_change", "business_logic", "baseline_control", "negative_control", "response_comparison", "session_state"]
  }
  if (/(authentication|login|session|token|password reset|account recovery|mfa|2fa)/.test(value)) {
    return ["identity_role", "session_state", "permission_boundary", "negative_control", "baseline_control", "response_comparison", "state_change", "endpoint_variant"]
  }
  return [...common, "identity_role", "permission_boundary", "session_state", "business_logic", "state_change", "cache_waf_environment"]
}

export interface FindingValidationInputCheck {
  id: FindingValidationCheckID
  status: FindingValidationStatus
  reason?: string
  evidence?: string
}

export interface FindingValidationAssessment {
  verdict: FindingValidationVerdict
  confidence: number
  checks: FindingValidationCheckRecord[]
  failedCheckIDs: string[]
  unknownCheckIDs: string[]
  summary: string
  nextStep: string
  output: string
  attemptCount: number
  attemptsRemaining: number
}

const CONTRADICTION_CHECKS = new Set([
  "reproducible",
  "request_path",
  "unexpected_behavior",
  "control_comparison",
  "benign_behavior_ruled_out",
])
const PRIMARY_CONTRADICTION_CHECKS = new Set(["reproducible", "request_path", "unexpected_behavior"])
const ATTEMPT_STRATEGIES = new Set<FindingValidationAttemptStrategy>(["baseline_control", "identity_role", "object_identifier", "http_method", "content_type", "session_state", "permission_boundary", "endpoint_variant", "business_logic", "cache_waf_environment", "timing_race", "negative_control", "response_comparison", "state_change", "other"])

export function assessFindingChecks(input: FindingValidationInputCheck[], attempts: FindingValidationAttemptInput[] = []): FindingValidationAssessment {
  if (input.length !== FINDING_VALIDATION_CHECKS.length) {
    throw new Error("Exactly 10 validation checks are required. Missing checks must be marked unknown, not omitted.")
  }

  const byID = new Map<string, FindingValidationInputCheck>()
  const attemptKeys = new Set<string>()
  for (const attempt of attempts) {
    const strategy = String(attempt.strategy).trim()
    const checkID = String(attempt.checkID).trim()
    const variation = String(attempt.variation).trim().toLowerCase().replace(/\s+/g, " ")
    if (!ATTEMPT_STRATEGIES.has(attempt.strategy) || !strategy || !checkID || !FINDING_VALIDATION_CHECKS.some((check) => check.id === checkID) || !["supports", "contradicts", "inconclusive"].includes(attempt.outcome) || typeof attempt.validConditions !== "boolean" || !variation || !attempt.hypothesis.trim() || !attempt.evidence.trim()) {
      throw new Error("Every validation attempt requires a strategy, unique variation, hypothesis, and concrete observed evidence.")
    }
    if (variation.length > 160 || attempt.hypothesis.length > 800 || attempt.evidence.length > 2000) {
      throw new Error("Validation attempt fields exceed safe length limits.")
    }
    const key = variation
    if (attemptKeys.has(key)) throw new Error("Duplicate validation attempt variation: " + key)
    attemptKeys.add(key)
  }
  for (const check of input) {
    if (byID.has(check.id)) throw new Error("Duplicate validation check: " + check.id)
    byID.set(check.id, check)
    if (check.status === "fail" && (!check.reason?.trim() || !check.evidence?.trim())) {
      throw new Error("A failed check needs a reason and concrete evidence. Use unknown when evidence is missing.")
    }
    if (check.status === "pass" && !check.evidence?.trim()) {
      throw new Error("A passed check needs concrete evidence from an observed test or artifact.")
    }
    if (check.status === "not_applicable" && !check.reason?.trim()) {
      throw new Error("A not_applicable check needs a reason explaining why it does not apply.")
    }
  }
  for (const definition of FINDING_VALIDATION_CHECKS) {
    if (!byID.has(definition.id)) throw new Error("Missing validation check: " + definition.id)
  }

  const checks: FindingValidationCheckRecord[] = FINDING_VALIDATION_CHECKS.map((definition) => {
    const supplied = byID.get(definition.id)!
    return {
      ...definition,
      status: supplied.status,
      reason: supplied.reason?.trim() || null,
      evidence: supplied.evidence?.trim() || null,
    }
  })
  const failed = checks.filter((check) => check.status === "fail")
  const unknown = checks.filter((check) => check.status === "unknown")
  const contradictions = failed.filter(
    (check) => CONTRADICTION_CHECKS.has(check.id) && Boolean(check.reason && check.evidence),
  )
  const hasPrimaryContradiction = contradictions.some((check) => PRIMARY_CONTRADICTION_CHECKS.has(check.id))
  const validAttempts = attempts.filter((attempt) => attempt.validConditions)
  const attemptContradictions = validAttempts.filter((attempt) => attempt.outcome === "contradicts")
  const attemptContradictedCheckIDs = new Set(attemptContradictions.map((attempt) => attempt.checkID))
  const attemptBackedContradictions = contradictions.filter((check) => attemptContradictedCheckIDs.has(check.id))
  const attemptPrimaryContradiction = attemptBackedContradictions.some((check) => PRIMARY_CONTRADICTION_CHECKS.has(check.id))
  const enoughDistinctAttempts = validAttempts.length >= FINDING_VALIDATION_MIN_ATTEMPTS
  // A false-positive verdict must not skip unresolved checklist questions. All ten checks
  // are required inputs, but UNKNOWN still means the assessment is incomplete and inconclusive.
  const falsePositive = enoughDistinctAttempts && unknown.length === 0 && contradictions.length >= 2 && hasPrimaryContradiction && attemptBackedContradictions.length >= 2 && attemptPrimaryContradiction

  const requiredPasses = [
    "reproducible",
    "request_path",
    "unexpected_behavior",
    "security_impact",
    "alternative_causes",
    "control_comparison",
    "evidence_complete",
    "benign_behavior_ruled_out",
    "reviewable",
  ]
  const byResult = new Map(checks.map((check) => [check.id, check]))
  const enoughToConfirm =
    requiredPasses.every((id) => byResult.get(id)?.status === "pass") &&
    ["pass", "not_applicable"].includes(byResult.get("identity_context")?.status ?? "unknown")

  const verdict: FindingValidationVerdict = falsePositive
    ? "false_positive"
    : enoughToConfirm
      ? "confirmed"
      : "inconclusive"
  // This is a deterministic rubric label, not a calibrated statistical probability.
  const confidence = verdict === "confirmed" ? 90 : verdict === "false_positive" ? 85 : 45
  const failedIDs = failed.map((check) => check.id)
  const unknownIDs = unknown.map((check) => check.id)
  const passed = checks.filter((check) => check.status === "pass")
  const notApplicable = checks.filter((check) => check.status === "not_applicable")
  const formatCheck = (check: FindingValidationCheckRecord) =>
    "#" + check.number + " [" + check.status.toUpperCase() + "] " + check.question +
    (check.reason ? " — Reason: " + check.reason : "") +
    (check.evidence ? " — Evidence: " + check.evidence : "")
  let summary: string
  let nextStep: string

  if (verdict === "false_positive") {
    const contradictionNumbers = contradictions.map((check) => "#" + check.number).join(", ")
    summary = "Classified as a likely false positive because evidence-backed contradictory checks " +
      contradictionNumbers + " conflict with the claim. Failed checks: " + failed.map((check) => "#" + check.number).join(", ") + "."
    nextStep = "Do not submit this hypothesis as a confirmed vulnerability. Keep this audit record; reopen only with new contradictory evidence or materially different conditions."
  } else if (verdict === "confirmed") {
    summary = "All required validation checks passed with recorded evidence. This supports the finding, but does not replace program rules or independent review."
    nextStep = "Prepare a minimal reproducible report with the control comparison, impact, and redacted evidence. Preserve uncertainty and limitations."
  } else {
    summary = "Inconclusive: evidence does not justify classifying this finding as confirmed or false positive. Failed checks: " +
      (failed.length ? failed.map((check) => "#" + check.number).join(", ") : "none") +
      "; unknown checks: " + (unknown.length ? unknown.map((check) => "#" + check.number).join(", ") : "none") + ". " +
      (enoughDistinctAttempts ? "The minimum of 20 distinct valid evidence-backed attempts has been reached." : "False-positive classification is blocked: " + validAttempts.length + "/20 distinct valid evidence-backed attempts are recorded.")
    nextStep = unknown.length > 0
      ? "Resolve the unknown checks before making a final verdict: " + unknown.map((check) => "#" + check.number + " " + check.id).join(", ") + ". Gather the missing evidence or record a justified not_applicable status where appropriate; 20 attempts do not override unanswered checklist questions."
      : enoughDistinctAttempts
        ? "Twenty distinct valid attempts are recorded, but a false-positive verdict still requires at least two failed contradiction checks backed by matching valid attempt outcomes, including one primary check. Reconcile the check evidence with the attempt log; keep the result inconclusive if they do not agree."
        : "Perform " + (FINDING_VALIDATION_MIN_ATTEMPTS - validAttempts.length) + " more distinct, case-specific tests under valid preconditions. Choose strategies based on the vulnerability hypothesis; compare identities, controls, state, methods, endpoints, timing, and benign explanations only when relevant. Do not count repeated identical requests, planned-but-unexecuted tests, invalid preconditions, or results without observed evidence. Stop if scope, safety, or authorization is unclear."
  }

  const output = [
    "Verdict: " + verdict + " (rubric confidence label: " + confidence + "/100; not a statistical probability)",
    "Check results: " + passed.length + " passed, " + failed.length + " failed, " + unknown.length + " unknown, " + notApplicable.length + " not applicable (10 total).",
    summary,
    "",
    "All ten checks (status, reason, and evidence):",
    ...checks.map(formatCheck),
    "",
    "Verification attempts: " + validAttempts.length + "/" + FINDING_VALIDATION_MIN_ATTEMPTS + " distinct valid evidence-backed attempts; " + Math.max(0, FINDING_VALIDATION_MIN_ATTEMPTS - validAttempts.length) + " remaining before false-positive eligibility.",
    "",
    "Next step: " + nextStep,
  ].join("\n")

  return {
    verdict,
    confidence,
    checks,
    failedCheckIDs: failedIDs,
    unknownCheckIDs: unknownIDs,
    summary,
    nextStep,
    output,
    attemptCount: validAttempts.length,
    attemptsRemaining: Math.max(0, FINDING_VALIDATION_MIN_ATTEMPTS - validAttempts.length),
  }
}

export namespace FindingValidation {
  export async function record(input: {
    sessionID: string
    vulnerabilityID: string
    checks: FindingValidationInputCheck[]
    attempts?: FindingValidationAttemptInput[]
  }) {
    const rootSessionID = Session.root(input.sessionID)
    const finding = Vulnerability.get(rootSessionID).find((row) => row.id === input.vulnerabilityID)
    if (!finding) {
      throw new Error("Finding " + input.vulnerabilityID + " was not found in the current session. No validation record was saved.")
    }

    // Global false-positive memory is advisory context only; never use similarity to
    // automatically classify or suppress a new finding.
    let priorFalsePositiveLessons: ReturnType<typeof FalsePositiveKnowledge.similar> = []
    try {
      priorFalsePositiveLessons = FalsePositiveKnowledge.similar({
        title: finding.title,
        description: finding.description,
        endpoint: finding.endpoint,
        limit: 5,
      })
    } catch (error) {
      console.warn("[cyberstrike] false-positive memory lookup failed:", error instanceof Error ? error.message : String(error))
    }

    const priorAttempts = Database.use((db) =>
      db
        .select({ attempts: FindingValidationTable.attempts })
        .from(FindingValidationTable)
        .where(and(eq(FindingValidationTable.session_id, rootSessionID), eq(FindingValidationTable.vulnerability_id, input.vulnerabilityID)))
        .all()
        .flatMap((row) => row.attempts ?? [])
        // Legacy records predate validConditions and therefore cannot count toward
        // a false-positive verdict until new valid evidence is recorded.
        .map((attempt) => ({ ...attempt, validConditions: attempt.validConditions === true })),
    )
    const newAttempts = input.attempts ?? []
    const currentKeys = new Set<string>()
    for (const attempt of newAttempts) {
      const key = attempt.variation.trim().toLowerCase().replace(/\s+/g, " ")
      if (currentKeys.has(key)) throw new Error("Duplicate validation attempt variation in this assessment: " + key)
      currentKeys.add(key)
    }
    const accumulated = new Map<string, FindingValidationAttemptRecord>()
    for (const attempt of [...priorAttempts, ...newAttempts]) {
      const key = attempt.variation.trim().toLowerCase().replace(/\s+/g, " ")
      const existing = accumulated.get(key)
      if (!existing) accumulated.set(key, attempt)
      else if (!existing.validConditions && attempt.validConditions) {
        // A corrected valid test can replace an earlier invalid setup attempt, but
        // an invalid retry must never downgrade a valid observation or erase proof.
        accumulated.set(key, attempt)
      }
    }
    const allAttempts = [...accumulated.values()]
    const assessment = assessFindingChecks(input.checks, allAttempts)
    const validationID = Identifier.ascending("finding_validation")
    const now = Date.now()
    Database.transaction((db) =>
      db
        .insert(FindingValidationTable)
        .values({
          id: validationID,
          session_id: rootSessionID,
          vulnerability_id: input.vulnerabilityID,
          verdict: assessment.verdict,
          confidence: assessment.confidence,
          checks: assessment.checks,
          attempts: allAttempts,
          attempt_count: assessment.attemptCount,
          failed_check_ids: assessment.failedCheckIDs,
          unknown_check_ids: assessment.unknownCheckIDs,
          summary: assessment.summary,
          next_step: assessment.nextStep,
          time_created: now,
          time_updated: now,
        })
        .run(),
    )

    const latestBlock = "\n\n[Latest finding validation]\n" + assessment.summary + "\n" + assessment.nextStep
    const description = finding.description.replace(/\n\n\[Latest finding validation\][\s\S]*$/, "") + latestBlock
    Vulnerability.update({
      sessionID: rootSessionID,
      id: input.vulnerabilityID,
      ...(assessment.verdict === "false_positive"
        ? { status: "false_positive" as const, candidate: null }
        : finding.status === "false_positive"
          ? { status: "new" as const, candidate: finding.severity }
          : {}),
      description,
    })

    if (assessment.verdict === "false_positive") {
      try {
        FalsePositiveKnowledge.record({
          finding,
          validationID,
          failedCheckIDs: assessment.failedCheckIDs,
          checks: assessment.checks,
          summary: assessment.summary,
        })
      } catch (error) {
        console.warn("[cyberstrike] false-positive lesson could not be saved:", error instanceof Error ? error.message : String(error))
      }
    } else if (finding.status === "false_positive") {
      // A later inconclusive/confirmed assessment reopens this finding. Retract its
      // old global lesson so stale conclusions cannot mislead future target hunts.
      try {
        FalsePositiveKnowledge.reopenForFinding(input.vulnerabilityID)
      } catch (error) {
        console.warn("[cyberstrike] superseded false-positive lesson could not be retracted:", error instanceof Error ? error.message : String(error))
      }
    }

    // Prefer the explicit workspace attribution already stored on the finding. Older findings
    // without target_id can still use unambiguous session observations as a conservative fallback.
    // Never infer a target from the title or write target validation details into global research memory.
    let targetNoteID: string | undefined
    let targetFilePath: string | undefined
    try {
      const workspaces = TargetMemory.list()
      const attributedWorkspace = finding.target_id
        ? workspaces.find((workspace) => workspace.id === finding.target_id)
        : undefined
      const observed = workspaces
        .filter((workspace) => TargetMemory.isObservedInSession(rootSessionID, workspace.targetURL))
        .sort((left, right) => {
          const hostSpecificity = right.hostname.length - left.hostname.length
          if (hostSpecificity) return hostSpecificity
          const leftPath = new URL(left.targetURL).pathname.length
          const rightPath = new URL(right.targetURL).pathname.length
          return rightPath - leftPath
        })
      const best = observed[0]
      const second = observed[1]
      const bestPathLength = best ? new URL(best.targetURL).pathname.length : 0
      const secondPathLength = second ? new URL(second.targetURL).pathname.length : 0
      const unambiguousBest = Boolean(
        best &&
          (!second ||
            best.hostname.length > second.hostname.length ||
            (best.hostname.length === second.hostname.length && bestPathLength > secondPathLength)),
      )
      const workspace = attributedWorkspace ?? (unambiguousBest ? best : undefined)
      if (workspace) {
        const note = await TargetMemory.addNote(workspace.targetURL, {
          kind: "finding",
          title: "Finding validation — " + finding.title,
          content: [
            "Validation of " + finding.title + " reached a " + assessment.verdict.replaceAll("_", " ") + " verdict (confidence rubric " + assessment.confidence + "/100, not a statistical probability). " + assessment.summary,
            "Across the recorded history there are " + assessment.attemptCount + " distinct evidence-backed attempts; the validation record is " + validationID + ". " + (assessment.failedCheckIDs.length ? "The evidence currently contradicts these checks: " + assessment.failedCheckIDs.join(", ") + ". " : "") + (assessment.unknownCheckIDs.length ? "These questions remain unresolved: " + assessment.unknownCheckIDs.join(", ") + ". " : ""),
            "Next, " + assessment.nextStep + " The full check and attempt history is stored in SQLite; this note summarizes the decision without duplicating raw request/response evidence. Revisit the conclusion if later evidence changes the interpretation.",
          ].filter(Boolean).join("\n\n"),
          source: "finding-validation",
          upsertByIdentity: true,
          identityKey: "finding:" + input.vulnerabilityID,
          ...(assessment.verdict === "confirmed" || assessment.verdict === "false_positive"
            ? { evidence: "SQLite finding-validation record " + validationID + "; verdict: " + assessment.verdict + "; distinct evidence-backed attempts: " + assessment.attemptCount + "; summary: " + assessment.summary }
            : {}),
          status: assessment.verdict === "confirmed" ? "confirmed" : assessment.verdict === "false_positive" ? "disproven" : "unverified",
          tags: ["finding-validation", assessment.verdict, ...assessment.failedCheckIDs.map((id) => "failed:" + id)],
        })
        targetNoteID = note.note.id
        targetFilePath = "findings/" + input.vulnerabilityID + ".validation-" + validationID + ".json"
        await TargetMemory.writeWorkspaceFile(note.workspace, targetFilePath, JSON.stringify({
          schemaVersion: 1,
          recordType: "finding-validation-reference",
          vulnerabilityID: input.vulnerabilityID,
          validationID,
          targetID: note.workspace.id,
          targetURL: note.workspace.targetURL,
          sessionID: rootSessionID,
          verdict: assessment.verdict,
          confidence: assessment.confidence,
          distinctAttempts: assessment.attemptCount,
          failedCheckIDs: assessment.failedCheckIDs,
          unknownCheckIDs: assessment.unknownCheckIDs,
          targetNoteID: note.note.id,
          recordedAt: new Date(now).toISOString(),
        }, null, 2) + "\n")
      }
    } catch (error) {
      // A note-file failure must not roll back the durable validation record or verdict.
      console.warn("[cyberstrike] target validation note could not be written:", error instanceof Error ? error.message : String(error))
    }

    const strategyPlan = recommendValidationStrategies([finding.title, finding.description, finding.endpoint].join(" "))
    const strategyGuidance = assessment.attemptsRemaining > 0
      ? "\nCase-specific strategy suggestions (choose only relevant, safe tests; do not blindly run all): " + strategyPlan.join(", ")
      : ""
    return {
      ...assessment,
      output: assessment.output + strategyGuidance + (
        priorFalsePositiveLessons.length
          ? "\n\n## Similar historical false-positive cases (advisory only)\n" +
            priorFalsePositiveLessons.map((lesson, index) =>
              (index + 1) + ". " + lesson.titlePattern +
              " — similarity " + lesson.similarity + "%; seen " + lesson.occurrences + " time(s); " +
              "prior contradictory checks: " + lesson.failedCheckIDs.join(", ") + ". " +
              "Benign explanation: " + lesson.benignExplanation +
              " This is a comparison clue, NOT proof that the current finding is false positive."
            ).join("\n")
          : "\n\nNo matching historical false-positive lesson was found in the shared database."
      ),
      strategyPlan,
      id: validationID,
      findingID: input.vulnerabilityID,
      targetNoteID,
      targetFilePath,
    }
  }

  export function history(input: { sessionID: string; vulnerabilityID: string; limit?: number }) {
    const sessionID = Session.root(input.sessionID)
    const limit = Math.max(1, Math.min(Math.floor(input.limit ?? 10), 100))
    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingValidationTable)
        .where(and(eq(FindingValidationTable.session_id, sessionID), eq(FindingValidationTable.vulnerability_id, input.vulnerabilityID)))
        .orderBy(desc(FindingValidationTable.time_created))
        .limit(limit)
        .all(),
    )
    return rows.map((row) => {
      // Old JSON snapshots have no validConditions field and must be shown as invalid.
      const attempts = (row.attempts ?? []).map((attempt) => ({
        ...attempt,
        validConditions: attempt.validConditions === true,
      }))
      return {
        ...row,
        attempts,
        // Keep history counts aligned with the current false-positive gate, not legacy totals.
        attempt_count: attempts.filter((attempt) => attempt.validConditions).length,
      }
    })
  }
}
