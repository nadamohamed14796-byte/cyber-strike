import z from "zod"
import { Tool } from "./tool"
import {
  FINDING_VALIDATION_CHECKS,
  FindingValidation,
  type FindingValidationInputCheck,
} from "../methodology/finding-validation"

const CHECK_ID = z.enum([
  "reproducible",
  "request_path",
  "unexpected_behavior",
  "security_impact",
  "identity_context",
  "alternative_causes",
  "control_comparison",
  "evidence_complete",
  "benign_behavior_ruled_out",
  "reviewable",
])

const CHECK_STATUS = z.enum(["pass", "fail", "unknown", "not_applicable"])

const DESCRIPTION = [
  "Validate an already-recorded finding with the ten required evidence-based checks.",
  "Fill one unique entry for every check ID below. Use status=unknown when the relevant test or evidence has not been collected; missing evidence is not proof of a false positive. For check #9, fail means concrete evidence supports an intended/benign explanation, not merely that you have not ruled one out.",
  "A status=fail requires BOTH a concrete reason and observable evidence. Do not guess a failure or invent evidence.",
  ...FINDING_VALIDATION_CHECKS.map((check) => "#" + check.number + " [" + check.id + "] " + check.question),
  "The tool stores every assessment in SQLite and appends the latest summary to the finding. It may set finding status to false_positive only when multiple evidence-backed contradictions are recorded, including at least one primary contradiction. Otherwise it returns confirmed or inconclusive according to the rubric.",
  "The result is a conservative rubric, not a statistical probability or replacement for human review. Do not run actions outside the existing approved scope; this tool does not change scope enforcement.",
].join("\n")

export const ValidateFindingTool = Tool.define("validate_finding", {
  description: DESCRIPTION,
  parameters: z.object({
    id: z.string().min(1).describe("Finding ID returned by report_vulnerability"),
    checks: z.array(
      z.object({
        id: CHECK_ID,
        status: CHECK_STATUS,
        reason: z.string().optional().describe("Evidence-grounded explanation, required for fail"),
        evidence: z.string().optional().describe("Concrete observed response/test result, required for fail"),
      }),
    ).length(10).describe("Exactly ten unique validation checks; use unknown rather than omit a check"),
  }),
  async execute(params, ctx) {
    try {
      const result = await FindingValidation.record({
        sessionID: ctx.sessionID,
        vulnerabilityID: params.id,
        checks: params.checks as FindingValidationInputCheck[],
      })
      return {
        title: "Finding validation: " + result.verdict,
        output: result.output,
        metadata: {
          validation_id: result.id,
          finding_id: result.findingID,
          target_note_id: result.targetNoteID,
          verdict: result.verdict,
          rubric_confidence: result.confidence,
          failed_checks: result.failedCheckIDs,
          unknown_checks: result.unknownCheckIDs,
        },
      }
    } catch (error) {
      return {
        title: "Finding validation could not be recorded",
        output: error instanceof Error ? error.message : String(error),
        metadata: { validation_error: true },
      }
    }
  },
})
