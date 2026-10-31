import z from "zod"
import { Tool } from "./tool"
import { Session } from "../session"
import { Vulnerability } from "../session/vulnerability"
import { VerificationLedger } from "../session/verification-ledger"
import { FindingValidation } from "../methodology/finding-validation"
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
    "Update the SAME approved finding after Impact Hunter has independently demonstrated a stronger security impact.",
    "This tool is restricted to the impact-hunter agent. It never creates a new finding.",
    "The latest ten-check validation must be confirmed, security_impact must be pass with concrete evidence, and the durable verification ledger for finding:<id> must contain a valid evidence-backed CONFIRMED result.",
    "Every supplied evidence_ref must exactly match a durable verification ledger evidenceRef for that finding. New severity must be strictly higher than the existing severity. Hypothetical chains, possible impact, response status alone, or a proposed attack path are not evidence.",
    "The tool appends the impact rationale and evidence references to the existing finding and synchronizes its target reference. It does not replace validation or triage; run validate_finding after the new impact test before using this tool.",
  ].join("\n"),
  parameters: z.object({
    id: z.string().trim().min(1).describe("Existing approved finding ID; this tool updates that record in place."),
    severity: Severity.describe("New severity, strictly higher than the current severity and justified by demonstrated additional impact."),
    demonstratedImpact: z.string().trim().min(40).max(3500).describe("Exact additional security consequence that was observed and reproducible; identify affected data, actor, privilege, or state."),
    severityRationale: z.string().trim().min(40).max(2000).describe("Why the new severity follows the program rubric, including prerequisites, scope, and limits."),
    evidence_refs: z.array(z.string().trim().min(3).max(500)).min(1).max(30)
      .describe("Exact evidenceRef strings already recorded in valid durable verification_attempt entries for hypothesis_key finding:<id>."),
  }),
  async execute(params, ctx) {
    if (ctx.agent !== "impact-hunter") {
      return {
        title: "Impact update blocked",
        output: "Only the dedicated Impact Hunter may raise an approved finding's severity. No record was changed.",
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
    if (SEVERITY_RANK[params.severity] <= SEVERITY_RANK[finding.severity]) {
      return {
        title: "Impact update blocked",
        output: "Requested severity " + params.severity + " is not higher than the existing " + finding.severity + ". The tool only accepts evidence-backed upward impact changes.",
        metadata: { updated: false, reason: "severity_not_higher", currentSeverity: finding.severity, requestedSeverity: params.severity },
      }
    }

    const latest = FindingValidation.history({ sessionID, vulnerabilityID: finding.id, limit: 1 })[0]
    if (!latest || latest.verdict !== "confirmed") {
      return {
        title: "Impact update blocked",
        output: "The latest validation is not confirmed. Run validate_finding with all ten evidence-backed checks after the additional impact tests. Current verdict: " + (latest?.verdict ?? "not_validated") + ".",
        metadata: { updated: false, reason: "latest_validation_not_confirmed", validationVerdict: latest?.verdict ?? "not_validated" },
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

    const hypothesisKey = "finding:" + finding.id
    const ledger = VerificationLedger.list({ sessionID, hypothesisKey })
    const confirmedEvidence = new Set(
      ledger
        .filter((attempt) => attempt.outcome === "confirmed" && attempt.validConditions && attempt.evidenceRef?.trim())
        .map((attempt) => attempt.evidenceRef!.trim()),
    )
    const missingRefs = params.evidence_refs.filter((ref) => !confirmedEvidence.has(ref))
    if (missingRefs.length) {
      return {
        title: "Impact update blocked",
        output: "These evidence_refs are not present as valid evidence-backed CONFIRMED entries in the durable ledger for " + hypothesisKey + ": " + missingRefs.join(", ") + ". Record the actual executed test first, revalidate, then retry.",
        metadata: { updated: false, reason: "evidence_reference_mismatch", missingEvidenceRefs: missingRefs },
      }
    }

    const evidenceBlock = [
      "",
      "[Impact Hunter — evidence-backed impact escalation]",
      "Additional demonstrated impact: " + redactTargetNoteSecrets(params.demonstratedImpact.trim()),
      "Severity rationale: " + redactTargetNoteSecrets(params.severityRationale.trim()),
      "Durable evidence references: " + params.evidence_refs.join(", "),
      "The updated severity is based only on the additional impact validated in the latest ten-check assessment.",
    ].join("\n")
    const updated = Vulnerability.update({
      sessionID,
      id: finding.id,
      severity: params.severity,
      description: finding.description.replace(/\n\n\[Impact Hunter — evidence-backed impact escalation\][\s\S]*$/, "") + evidenceBlock,
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
        "New severity: " + params.severity,
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
        evidence_refs: params.evidence_refs,
        target_reference: targetReference ?? null,
        target_reference_error: targetReferenceError ?? null,
      },
    }
  },
})
