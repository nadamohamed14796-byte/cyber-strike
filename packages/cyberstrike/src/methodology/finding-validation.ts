import { and, desc, eq } from "../storage/db"
import { Database } from "../storage/db"
import { Identifier } from "../id/id"
import { Session } from "../session"
import { Vulnerability } from "../session/vulnerability"
import { TargetMemory } from "../target"
import {
  FindingValidationTable,
  type FindingValidationCheckRecord,
  type FindingValidationStatus,
  type FindingValidationVerdict,
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
}

const CONTRADICTION_CHECKS = new Set([
  "reproducible",
  "request_path",
  "unexpected_behavior",
  "control_comparison",
  "benign_behavior_ruled_out",
])
const PRIMARY_CONTRADICTION_CHECKS = new Set(["reproducible", "request_path", "unexpected_behavior"])

export function assessFindingChecks(input: FindingValidationInputCheck[]): FindingValidationAssessment {
  if (input.length !== FINDING_VALIDATION_CHECKS.length) {
    throw new Error("Exactly 10 validation checks are required. Missing checks must be marked unknown, not omitted.")
  }

  const byID = new Map<string, FindingValidationInputCheck>()
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
  const falsePositive = contradictions.length >= 2 && hasPrimaryContradiction

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
  const formatFailed = failed.map((check) => "#" + check.number + " " + check.question + " — " + check.reason)
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
      "; unknown checks: " + (unknown.length ? unknown.map((check) => "#" + check.number).join(", ") : "none") + "."
    nextStep = "Run controlled tests for unknown or failed checks, prioritizing reproducibility, the expected request path, a safe baseline/control, and evidence of real impact. Do not promote the record based on missing evidence."
  }

  const output = [
    "Verdict: " + verdict + " (rubric confidence label: " + confidence + "/100; not a statistical probability)",
    summary,
    ...(formatFailed.length ? ["", "Failed checks:", ...formatFailed] : []),
    ...(unknown.length ? ["", "Unknown checks:", ...unknown.map((check) => "#" + check.number + " " + check.question + (check.reason ? " — " + check.reason : ""))] : []),
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
  }
}

export namespace FindingValidation {
  export async function record(input: {
    sessionID: string
    vulnerabilityID: string
    checks: FindingValidationInputCheck[]
  }) {
    const rootSessionID = Session.root(input.sessionID)
    const finding = Vulnerability.get(rootSessionID).find((row) => row.id === input.vulnerabilityID)
    if (!finding) {
      throw new Error("Finding " + input.vulnerabilityID + " was not found in the current session. No validation record was saved.")
    }

    const assessment = assessFindingChecks(input.checks)
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
        : assessment.verdict === "confirmed"
          ? { status: "approved" as const, candidate: null }
          : {}),
      description,
    })

    // Save the outcome in target-specific notes only when an existing workspace is
    // unambiguously matched to observations from this session tree. Never infer a target
    // from a finding title or write validation details into global research memory.
    let targetNoteID: string | undefined
    try {
      const observed = TargetMemory.list()
        .filter((workspace) => TargetMemory.isObservedInSession(rootSessionID, workspace.targetURL))
        .sort((left, right) => {
          const hostSpecificity = right.hostname.length - left.hostname.length
          if (hostSpecificity) return hostSpecificity
          const leftPath = new URL(left.targetURL).pathname.length
          const rightPath = new URL(right.targetURL).pathname.length
          return rightPath - leftPath
        })
      const workspace = observed[0]
      if (workspace) {
        const note = await TargetMemory.addNote(workspace.targetURL, {
          kind: "finding",
          title: "Finding validation — " + finding.title,
          content: [
            "Finding ID: " + input.vulnerabilityID,
            "Validation ID: " + validationID,
            "Verdict: " + assessment.verdict,
            assessment.summary,
            assessment.nextStep,
            "Failed checks: " + (assessment.failedCheckIDs.length ? assessment.failedCheckIDs.join(", ") : "none"),
            "Unknown checks: " + (assessment.unknownCheckIDs.length ? assessment.unknownCheckIDs.join(", ") : "none"),
            "Check history is stored in the SQLite finding_validation table. This note intentionally excludes raw request/response evidence.",
          ].join("\n"),
          source: "finding-validation:" + validationID,
          status: assessment.verdict === "confirmed" ? "confirmed" : assessment.verdict === "false_positive" ? "disproven" : "unverified",
          tags: ["finding-validation", assessment.verdict, ...assessment.failedCheckIDs.map((id) => "failed:" + id)],
        })
        targetNoteID = note.note.id
      }
    } catch (error) {
      // A note-file failure must not roll back the durable validation record or verdict.
      console.warn("[cyberstrike] target validation note could not be written:", error instanceof Error ? error.message : String(error))
    }

    return { ...assessment, id: validationID, findingID: input.vulnerabilityID, targetNoteID }
  }

  export function history(input: { sessionID: string; vulnerabilityID: string; limit?: number }) {
    const sessionID = Session.root(input.sessionID)
    const limit = Math.max(1, Math.min(Math.floor(input.limit ?? 10), 100))
    return Database.use((db) =>
      db
        .select()
        .from(FindingValidationTable)
        .where(and(eq(FindingValidationTable.session_id, sessionID), eq(FindingValidationTable.vulnerability_id, input.vulnerabilityID)))
        .orderBy(desc(FindingValidationTable.time_created))
        .limit(limit)
        .all(),
    )
  }
}
