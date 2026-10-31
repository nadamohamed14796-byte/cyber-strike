import z from "zod"
import { Tool } from "./tool"
import { Session } from "../session"
import { Vulnerability } from "../session/vulnerability"
import { VerificationLedger } from "../session/verification-ledger"
import { FindingValidation, hasCompleteConfirmedValidation } from "../methodology/finding-validation"
import { TargetMemory } from "../target"
import { persistTargetFindingLink } from "../methodology/finding-reference"
import { redactTargetNoteSecrets } from "../target/redact"

const Severity = z.enum(["critical", "high", "medium", "low", "info"])
const SEVERITY_RANK: Record<z.infer<typeof Severity>, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

export const UpdateFindingImpactTool = Tool.define("update_finding_impact", {
  description: [
    "Update the SAME approved finding after Impact Hunter has independently demonstrated additional or stronger security impact. The severity may stay the same when the additional impact is real but remains in the same program severity band.",
    "This tool is restricted to the impact-hunter agent. It never creates a new finding.",
    "The latest ten-check validation must be confirmed, security_impact must be pass with concrete evidence, and a separate impact hypothesis under finding:<id>:impact:<slug> must have a valid evidence-backed CONFIRMED outcome in the durable verification ledger.",
    "Every supplied evidence_ref must exactly match a valid CONFIRMED durable verification ledger entry under a new finding:<id>:impact:<slug> hypothesis key, and that evidence must be newer than the baseline validation ID supplied at handoff. Severity may stay the same or increase, never decrease; an unchanged severity records a stronger consequence that remains in the same program band. Hypothetical chains, possible impact, response status alone, or a proposed attack path are not evidence.",
    "The tool appends the impact rationale and evidence references to the existing finding and synchronizes its target reference. It does not replace validation or triage; run validate_finding after the new impact test before using this tool.",
  ].join("\n"),
  parameters: z.object({
    id: z.string().trim().min(1).describe("Existing approved finding ID; this tool updates that record in place."),
    severity: Severity.describe("Evidence-supported resulting severity. It may equal the current severity when the new impact remains in the same band, or increase when the program rubric justifies it; it may never decrease."),
    demonstratedImpact: z.string().trim().min(40).max(3500).describe("Exact additional security consequence that was observed and reproducible; identify affected data, actor, privilege, or state."),
    severityRationale: z.string().trim().min(40).max(2000).describe("Why the new severity follows the program rubric, including prerequisites, scope, and limits."),
    baseline_validation_id: z.string().trim().min(1).describe("Exact baseline_validation_id supplied in this Impact Hunter task handoff."),
    impact_hypothesis_key: z.string().trim().min(1).describe("A new durable ledger key shaped exactly like finding:<id>:impact:<short-hypothesis-slug>; do not reuse the terminal initial finding:<id> key."),
    evidence_refs: z.array(z.string().trim().min(3).max(500)).min(1).max(30)
      .describe("Exact evidenceRef strings recorded in valid CONFIRMED durable verification_attempt entries for the supplied impact_hypothesis_key, after the baseline validation."),
  }),
  async execute(params, ctx): Promise<{ title: string; output: string; metadata: Tool.Metadata }> {
    if (ctx.agent !== "impact-hunter") {
      return {
        title: "Impact update blocked",
        output: "Only the dedicated Impact Hunter may update impact on an approved finding. No record was changed.",
        metadata: { updated: false, reason: "impact_hunter_only" },
      }
    }

    const sessionID = Session.root(ctx.sessionID)
    const finding = Vulnerability.get(sessionID).find((row) => row.id === params.id)
    if (!finding) {
      return { title: "Impact update blocked", output: "Finding " + params.id + " was not found in the current session. No record was changed.", metadata: { updated: false, reason: "finding_not_found" } }
    }
    if (finding.status !== "approved") {
      return {
        title: "Impact update blocked",
        output: "Finding must already be explicitly approved before impact escalation. Current status: " + finding.status + ".",
        metadata: { updated: false, reason: "finding_not_approved", currentStatus: finding.status },
      }
    }
    if (SEVERITY_RANK[params.severity] < SEVERITY_RANK[finding.severity]) {
      return {
        title: "Impact update blocked",
        output: "Requested severity " + params.severity + " is lower than the existing " + finding.severity + ". Impact Hunter may preserve the current band or raise it with proof, but may never downgrade it.",
        metadata: { updated: false, reason: "severity_downgrade", currentSeverity: finding.severity, requestedSeverity: params.severity },
      }
    }
    const severityChanged = params.severity !== finding.severity

    const validationHistory = FindingValidation.history({ sessionID, vulnerabilityID: finding.id, limit: 100 })
    const baselineValidation = validationHistory.find((item) => item.id === params.baseline_validation_id)
    const latest = validationHistory[0]
    if (!baselineValidation || !hasCompleteConfirmedValidation(baselineValidation)) {
      return {
        title: "Impact update blocked",
        output: "baseline_validation_id does not match a stored confirmed validation for this finding. Re-read the exact handoff context; no severity change was made.",
        metadata: { updated: false, reason: "baseline_validation_not_found" },
      }
    }
    if (!latest || !hasCompleteConfirmedValidation(latest) || latest.id === baselineValidation.id || latest.time_created <= baselineValidation.time_created) {
      return {
        title: "Impact update blocked",
        output: "A newer confirmed ten-check validation is required after the Impact Hunter handoff. Run validate_finding after the new impact tests; the initial approval validation is not sufficient.",
        metadata: { updated: false, reason: "newer_confirmed_validation_required", latestValidationID: latest?.id ?? null, baselineValidationID: baselineValidation.id },
      }
    }
    const impactCheck = latest.checks.find((check) => check.id === "security_impact")
    if (!impactCheck || impactCheck.status !== "pass" || !impactCheck.evidence?.trim()) {
      return {
        title: "Impact update blocked",
        output: "The latest confirmed validation does not contain a passed security_impact check with concrete evidence. No severity change was made.",
        metadata: { updated: false, reason: "security_impact_evidence_missing" },
      }
    }

    const requiredImpactPrefix = "finding:" + finding.id + ":impact:"
    const impactHypothesisKey = params.impact_hypothesis_key
    if (!impactHypothesisKey.startsWith(requiredImpactPrefix) || !/^[a-z0-9][a-z0-9._-]{2,100}$/i.test(impactHypothesisKey.slice(requiredImpactPrefix.length))) {
      return {
        title: "Impact update blocked",
        output: "impact_hypothesis_key must be a distinct stable key with the shape " + requiredImpactPrefix + "<short-slug>. The original finding:<id> key is terminal and cannot be reused for additional testing.",
        metadata: { updated: false, reason: "invalid_impact_hypothesis_key", expectedPrefix: requiredImpactPrefix },
      }
    }
    const impactLedger = VerificationLedger.list({ sessionID, hypothesisKey: impactHypothesisKey })
    const confirmedImpactEvidence = new Set(
      impactLedger
        .filter((attempt) =>
          attempt.outcome === "confirmed" &&
          attempt.validConditions &&
          Boolean(attempt.evidenceRef?.trim()) &&
          attempt.timeCreated >= baselineValidation.time_created &&
          attempt.timeCreated <= latest.time_created,
        )
        .map((attempt) => attempt.evidenceRef!.trim()),
    )
    const missingRefs = params.evidence_refs.filter((ref) => !confirmedImpactEvidence.has(ref))
    if (missingRefs.length) {
      return {
        title: "Impact update blocked",
        output: "These evidence_refs are not present as valid, post-handoff CONFIRMED entries under " + impactHypothesisKey + ": " + missingRefs.join(", ") + ". Record the executed impact test under that exact new hypothesis key, revalidate the finding, then retry.",
        metadata: { updated: false, reason: "evidence_reference_mismatch", missingEvidenceRefs: missingRefs, impactHypothesisKey },
      }
    }

    const evidenceBlock = [
      "",
      "[Impact Hunter — evidence-backed impact escalation]",
      "Additional demonstrated impact: " + redactTargetNoteSecrets(params.demonstratedImpact.trim()),
      "Severity rationale: " + redactTargetNoteSecrets(params.severityRationale.trim()),
      "Durable evidence references: " + params.evidence_refs.join(", "),
      "The retained or raised severity is based only on the additional impact validated in the latest ten-check assessment.",
    ].join("\n")
    // FindingValidation.record replaces the trailing [Latest finding validation]
    // block on the next validation run. Keep all Impact Hunter history BEFORE that
    // replaceable tail so subsequent ten-check validations cannot erase escalation
    // evidence or earlier severity transitions.
    const validationMarker = "\n\n[Latest finding validation]"
    const validationIndex = finding.description.lastIndexOf(validationMarker)
    const descriptionCore = validationIndex >= 0
      ? finding.description.slice(0, validationIndex)
      : finding.description
    const validationTail = validationIndex >= 0
      ? finding.description.slice(validationIndex)
      : ""
    const updatedDescription = descriptionCore + evidenceBlock + validationTail

    const updated = Vulnerability.update({
      sessionID,
      id: params.id,
      severity: params.severity,
      description: updatedDescription,
      expectedStatus: "approved",
    })
    if (!updated) {
      return { title: "Impact update not applied", output: "The finding changed before the update could be committed. Re-read it and reconcile the latest validation/evidence; nothing was overwritten.", metadata: { updated: false, reason: "concurrent_change" } }
    }

    const updatedFinding = Vulnerability.get(sessionID).find((row) => row.id === finding.id)!
    let targetReference: { filePath: string; targetURL: string } | undefined
    let targetReferenceError: string | undefined
    try {
      const workspace = updatedFinding.target_id
        ? TargetMemory.list().find((item) => item.id === updatedFinding.target_id)
        : undefined
      if (workspace) {
        const saved = await persistTargetFindingLink({
          workspace,
          vulnerability: updatedFinding,
          sessionID,
          validationState: "confirmed",
        })
        targetReference = { filePath: saved.filePath, targetURL: saved.workspace.targetURL }
      }
    } catch (error) {
      targetReferenceError = error instanceof Error ? error.message : String(error)
    }

    return {
      title: "Impact Hunter updated " + finding.id + " → " + params.severity,
      output: [
        "Updated the existing finding in place; no duplicate was created.",
        "Previous severity: " + finding.severity,
        severityChanged
          ? "New severity: " + params.severity
          : "Severity unchanged: " + finding.severity + " (additional demonstrated impact recorded within the same severity band).",
        "Additional demonstrated impact: " + redactTargetNoteSecrets(params.demonstratedImpact.trim()),
        "Severity rationale: " + redactTargetNoteSecrets(params.severityRationale.trim()),
        "Evidence references: " + params.evidence_refs.join(", "),
        targetReference ? "Target reference synchronized: " + targetReference.targetURL + "/" + targetReference.filePath : "",
        targetReferenceError ? "Warning: target reference sync failed: " + targetReferenceError : "",
      ].filter(Boolean).join("\n"),
      metadata: {
        updated: true,
        findingID: finding.id,
        previousSeverity: finding.severity,
        severity: params.severity,
        severityChanged,
        evidence_refs: params.evidence_refs,
        target_reference: targetReference ?? null,
        target_reference_error: targetReferenceError ?? null,
      },
    }
  },
})
