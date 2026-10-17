import z from "zod"
import { Tool } from "./tool"
import { ReportKnowledge } from "../learning/report-knowledge"
import { Session } from "../session"
import {
  FINDING_VALIDATION_CHECKS,
  FindingValidation,
  type FindingValidationInputCheck,
  type FindingValidationAttemptInput,
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
const ATTEMPT_STRATEGY = z.enum(["baseline_control", "identity_role", "object_identifier", "http_method", "content_type", "session_state", "permission_boundary", "endpoint_variant", "business_logic", "cache_waf_environment", "timing_race", "negative_control", "response_comparison", "state_change", "other"])
const ATTEMPT_OUTCOME = z.enum(["supports", "contradicts", "inconclusive"])

const DESCRIPTION = [
  "Validate an already-recorded finding with the ten required evidence-based checks.",
  "Fill one unique entry for every check ID below. Use status=unknown when the relevant test or evidence has not been collected; missing evidence is not proof of a false positive. For check #9, fail means concrete evidence supports an intended/benign explanation, not merely that you have not ruled one out.",
  "A status=fail requires BOTH a concrete reason and observable evidence. Do not guess a failure or invent evidence.",
  "HTTP status handling: 403 means access was denied by some layer, not automatically that the endpoint is secure or vulnerable. Check the authenticated/anonymous baseline, session validity, role/ownership, required headers/CSRF, redirects, and whether a gateway/WAF produced the response. 404 may mean a genuinely absent route/resource or intentional concealment of an unauthorized resource (soft-404); compare a known-valid in-scope control, resource ownership, method, and response semantics where safe. A 403/404, generic error, or one failed request must never by itself pass or fail the vulnerability claim; record the actual evidence and use unknown/inconclusive when preconditions cannot be established.",
  "For security_impact, status=pass must describe a demonstrated security consequence (for example, unauthorized access to another user's non-public data, an unauthorized state change, or a reproducible exploit path with concrete effect). The existence of a weakness, missing security header, scanner label, theoretical chain, or generic statement such as 'may expose users' is not impact evidence. If only a missing header or hardening gap was observed and no relevant browser behavior, sensitive action, or exploit path was demonstrated, mark security_impact=unknown and keep the verdict inconclusive; do not approve the finding.",
  "False-positive classification requires at least 20 distinct, evidence-backed test variations executed under valid preconditions across validation calls, plus multiple evidence-backed contradictions including a primary contradiction. Attempts with invalid scope, identity, session, or setup do not count. A missing or failed test alone never proves false positive.",
  "Supply attempts actually executed in this validation call. Each attempt must include a case-specific strategy, unique variation key, hypothesis, outcome, concrete observed evidence, and validConditions=true only when scope, identity, session, and setup preconditions were valid. Invalid attempts remain recorded but do not count toward the 20-attempt false-positive gate. Do not submit planned tests, repeat identical requests under different labels, or count an attempt without an observed result. Prefer a strategy appropriate to the vulnerability type; do not blindly run every strategy. Stop if authorization, scope, or safety is unclear.",
  "Strategy examples: compare owner/non-owner roles for authorization issues; vary object IDs and state transitions for IDOR/business logic; use a baseline and negative control; compare relevant methods/content types only when the endpoint supports them; investigate cache/WAF/timing only when observations suggest those causes. Every test must stay inside authorized scope and avoid destructive effects.",
  ...FINDING_VALIDATION_CHECKS.map((check) => "#" + check.number + " [" + check.id + "] " + check.question),
  "The tool stores every assessment in SQLite and appends the latest summary to the finding. It may set finding status to false_positive only after 20 distinct valid attempts and multiple evidence-backed contradictions, including at least one primary contradiction. Otherwise it returns confirmed or inconclusive according to the rubric.",
  "When exactly one existing target workspace is the most specific match for observations in this session tree, it also saves a target-specific summary note and reports its note ID. Ambiguous/unobserved targets receive no note; raw request/response evidence is not copied into the note.",
  "Optional research_reference_ids must contain only exact Knowledge record IDs for shared public references that materially influenced this validation. A confirmed verdict records reference usefulness for ranking; inconclusive and false-positive results are recorded as observed only and never disprove the source report.",
  "The result is a conservative rubric, not a statistical probability or replacement for human review. Do not run actions outside the existing approved scope; this tool does not change scope enforcement.",
].join("\n")

const ValidateFindingParameters = z.object({
    id: z.string().min(1).describe("Finding ID returned by report_vulnerability"),
    research_reference_ids: z.array(z.string().trim().min(1).max(128))
      .max(8)
      .optional()
      .describe("Exact Knowledge record IDs returned by research_knowledge or the automatic research context; include only references that materially influenced this validation"),
    attempts: z.array(z.object({
      strategy: ATTEMPT_STRATEGY,
      checkID: CHECK_ID.describe("Which of the ten validation checks this attempt tests"),
      variation: z.string().trim().min(3).max(160).describe("Unique case-specific test variation, not a renamed duplicate"),
      hypothesis: z.string().trim().min(8).max(800),
      outcome: ATTEMPT_OUTCOME,
      evidence: z.string().trim().min(8).max(2000).describe("Observed response, artifact, or concrete result; never a plan"),
      validConditions: z.boolean().describe("True only if scope, identity/session, and test preconditions were valid; false attempts do not count toward the 20-attempt false-positive gate"),
    })).max(100).optional().describe("New tests actually executed in this call. Distinct valid attempts accumulate across validations; 20 valid attempts are required before a false-positive verdict."),
    checks: z.array(
      z.object({
        id: CHECK_ID,
        status: CHECK_STATUS,
        reason: z.string().optional().describe("Evidence-grounded explanation, required for fail"),
        evidence: z.string().optional().describe("Concrete observed response/test result, required for fail"),
      }),
    ).length(10).describe("Exactly ten unique validation checks; use unknown rather than omit a check"),
  })

export const ValidateFindingTool = Tool.define<typeof ValidateFindingParameters, Tool.Metadata>("validate_finding", {
  description: DESCRIPTION,
  parameters: ValidateFindingParameters,
  async execute(params, ctx) {
    try {
      const result = await FindingValidation.record({
        sessionID: ctx.sessionID,
        vulnerabilityID: params.id,
        checks: params.checks as FindingValidationInputCheck[],
        attempts: params.attempts as FindingValidationAttemptInput[] | undefined,
      })
      let researchFeedbackRecorded = 0
      const feedbackOutcome = result.verdict === "confirmed" ? "useful" : "observed"
      for (const reportID of new Set(params.research_reference_ids ?? [])) {
        if (ReportKnowledge.recordReferenceUse({
          reportID,
          sessionID: Session.root(ctx.sessionID),
          outcome: feedbackOutcome,
          signal: "finding-validation:" + result.verdict,
          metadata: {
            validation_verdict: result.verdict,
            feedback_basis: "agent-marked-materially-influential",
          },
        })) researchFeedbackRecorded++
      }
      return {
        title: "Finding validation: " + result.verdict,
        output: result.output + (
          result.targetNoteID
            ? "\nTarget-specific validation note saved: " + result.targetNoteID + (result.targetFilePath ? "\nTarget validation file: " + result.targetFilePath : "")
            : "\nNo target note was written because no uniquely matched, observed target workspace was available."
        ),
        metadata: {
          validation_id: result.id,
          finding_id: result.findingID,
          target_note_id: result.targetNoteID,
          target_file_path: result.targetFilePath,
          verdict: result.verdict,
          rubric_confidence: result.confidence,
          distinct_attempts: result.attemptCount,
          attempts_remaining_before_false_positive: result.attemptsRemaining,
          recommended_strategies: result.strategyPlan,
          failed_checks: result.failedCheckIDs,
          unknown_checks: result.unknownCheckIDs,
          research_reference_feedback_recorded: researchFeedbackRecorded,
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
