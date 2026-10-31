import z from "zod"
import { Tool } from "./tool"
import { Session } from "../session"
import { Vulnerability } from "../session/vulnerability"
import { VerificationLedger } from "../session/verification-ledger"
import { TargetMemory } from "../target"
import { persistTargetFindingLink } from "../methodology/finding-reference"
import { redactTargetNoteSecrets } from "../target/redact"

export const UpdateFindingEvidenceTool = Tool.define("update_finding_evidence", {
  description: [
    "Persist a reproducible PoC and its evidence onto the SAME NEW candidate after Impact Hunter closes a proof gap.",
    "This tool is restricted to Impact Hunter. It never creates a second finding and cannot approve the candidate or change its severity.",
    "The supplied proof_hypothesis_key must be finding:<id>:poc:<slug>, and every evidence_ref must exactly match a valid, evidence-backed CONFIRMED record in the durable verification ledger for that hypothesis.",
    "Use only after executing a safe, in-scope test with valid prerequisites and preserving the actual request/response or source/artifact evidence. A reference payload or a claimed result is not proof.",
    "After this update, run the full ten-check validate_finding workflow; only an evidence-backed CONFIRMED result plus explicit triage approval makes the finding reportable.",
  ].join("\n"),
  parameters: z.object({
    id: z.string().trim().min(1).describe("Existing NEW finding ID; update this record in place."),
    proof_hypothesis_key: z.string().trim().min(1).describe("New terminal proof hypothesis key shaped finding:<id>:poc:<short-slug>."),
    poc: z.string().trim().min(80).max(6000).describe("Reproducible proof: prerequisites, baseline request/response, proof request/response, expected versus actual behavior, and a concise diff. Redact reusable credentials and personal data."),
    steps_to_reproduce: z.string().trim().min(40).max(4000).describe("Numbered steps using tester-owned accounts/fixtures and sanitized request details."),
    demonstrated_impact: z.string().trim().min(40).max(2500).describe("The exact security-boundary consequence demonstrated by this proof, or the narrower observed behavior when impact remains limited."),
    evidence_refs: z.array(z.string().trim().min(3).max(500)).min(1).max(30)
      .describe("Exact evidenceRef values already persisted under proof_hypothesis_key as valid CONFIRMED verification attempts."),
    description_addendum: z.string().trim().min(20).max(2500).optional().describe("Optional additional root-cause detail grounded in the same PoC evidence."),
    recommendation: z.string().trim().min(20).max(1500).optional().describe("Optional concrete fix/regression suggestion, not a substitute for proof."),
    source_file: z.string().trim().min(1).max(1000).optional().describe("Optional exact source file path verified during the investigation."),
    source_line_start: z.number().int().positive().optional().describe("Optional starting line for the verified source location."),
    source_line_end: z.number().int().positive().optional().describe("Optional ending line for the verified source location."),
  }),
  async execute(params, ctx) {
    if (ctx.agent !== "impact-hunter") {
      return {
        title: "Finding evidence update blocked",
        output: "Only Impact Hunter may persist a PoC-gap result onto a candidate. No record was changed.",
        metadata: { updated: false, reason: "impact_hunter_only" },
      }
    }

    const sessionID = Session.root(ctx.sessionID)
    const finding = Vulnerability.get(sessionID).find((row) => row.id === params.id)
    if (!finding) {
      return { title: "Finding evidence update blocked", output: "Finding " + params.id + " was not found in the current session.", metadata: { updated: false, reason: "finding_not_found" } }
    }
    if (finding.status !== "new") {
      return {
        title: "Finding evidence update blocked",
        output: "Only a NEW candidate can receive a proof-gap update. Current status: " + finding.status + ". Use update_finding_impact only for an approved finding.",
        metadata: { updated: false, reason: "finding_not_new", currentStatus: finding.status },
      }
    }
    if (finding.poc?.trim()) {
      return {
        title: "Finding evidence update blocked",
        output: "This candidate already has a PoC. Do not overwrite it; validate the current PoC or create a materially distinct hypothesis.",
        metadata: { updated: false, reason: "poc_already_present" },
      }
    }

    const requiredPrefix = "finding:" + finding.id + ":poc:"
    const proofHypothesisKey = params.proof_hypothesis_key
    if (!proofHypothesisKey.startsWith(requiredPrefix) || !/^[a-z0-9][a-z0-9._-]{2,100}$/i.test(proofHypothesisKey.slice(requiredPrefix.length))) {
      return {
        title: "Finding evidence update blocked",
        output: "proof_hypothesis_key must have the distinct shape " + requiredPrefix + "<short-slug>.",
        metadata: { updated: false, reason: "invalid_proof_hypothesis_key", expectedPrefix: requiredPrefix },
      }
    }

    const ledger = VerificationLedger.list({ sessionID, hypothesisKey: proofHypothesisKey })
    const confirmedRefs = new Set(
      ledger
        .filter((attempt) =>
          attempt.outcome === "confirmed" &&
          attempt.validConditions &&
          Boolean(attempt.evidenceRef?.trim()),
        )
        .map((attempt) => attempt.evidenceRef!.trim()),
    )
    const missingRefs = params.evidence_refs.filter((ref) => !confirmedRefs.has(ref))
    if (missingRefs.length) {
      return {
        title: "Finding evidence update blocked",
        output: "These evidence references do not match valid CONFIRMED durable proof attempts under " + proofHypothesisKey + ": " + missingRefs.join(", ") + ". Record the executed test and preserve its evidence before retrying.",
        metadata: { updated: false, reason: "evidence_reference_mismatch", missingEvidenceRefs: missingRefs },
      }
    }

    const evidenceBlock = [
      "",
      "[Impact Hunter — PoC gap closed; pending full validation]",
      "Demonstrated impact: " + redactTargetNoteSecrets(params.demonstrated_impact.trim()),
      "PoC proof hypothesis: " + proofHypothesisKey,
      "Durable evidence references: " + params.evidence_refs.join(", "),
      params.description_addendum ? "Additional root-cause detail: " + redactTargetNoteSecrets(params.description_addendum.trim()) : "",
    ].filter(Boolean).join("\n")

    const validationMarker = "\n\n[Latest finding validation]"
    const validationIndex = finding.description.lastIndexOf(validationMarker)
    const descriptionCore = validationIndex >= 0
      ? finding.description.slice(0, validationIndex)
      : finding.description
    const validationTail = validationIndex >= 0
      ? finding.description.slice(validationIndex)
      : ""
    const updated = Vulnerability.update({
      sessionID,
      id: finding.id,
      description: descriptionCore + evidenceBlock + validationTail,
      poc: redactTargetNoteSecrets(params.poc.trim()),
      steps_to_reproduce: redactTargetNoteSecrets(params.steps_to_reproduce.trim()),
      business_impact: redactTargetNoteSecrets(params.demonstrated_impact.trim()),
      ...(params.recommendation ? { recommendation: redactTargetNoteSecrets(params.recommendation.trim()) } : {}),
      ...(params.source_file ? { file: params.source_file, line_start: params.source_line_start, line_end: params.source_line_end } : {}),
      expectedStatus: "new",
    })
    if (!updated) {
      return { title: "Finding evidence update not applied", output: "The finding changed before the PoC update could be committed. Re-read it and reconcile the current validation/status; no success was reported.", metadata: { updated: false, reason: "concurrent_change" } }
    }

    const savedFinding = Vulnerability.get(sessionID).find((row) => row.id === finding.id)!
    let targetReference: { filePath: string; targetURL: string } | undefined
    let targetReferenceError: string | undefined
    try {
      if (savedFinding.target_id) {
        const workspace = TargetMemory.list().find((item) => item.id === savedFinding.target_id)
        if (workspace) {
          const saved = await persistTargetFindingLink({
            workspace,
            vulnerability: savedFinding,
            sessionID,
            validationState: "pending",
          })
          targetReference = { filePath: saved.filePath, targetURL: saved.workspace.targetURL }
        }
      }
    } catch (error) {
      targetReferenceError = error instanceof Error ? error.message : String(error)
    }

    return {
      title: "PoC saved to candidate " + finding.id,
      output: [
        "Updated the existing candidate in place; no duplicate was created.",
        "Lifecycle remains NEW / unapproved. The PoC is evidence for validation, not automatic confirmation.",
        "PoC proof hypothesis: " + proofHypothesisKey,
        "Evidence references: " + params.evidence_refs.join(", "),
        targetReference ? "Target reference synchronized: " + targetReference.targetURL + "/" + targetReference.filePath : "",
        targetReferenceError ? "Warning: target reference sync failed: " + targetReferenceError : "",
        "Next: run all ten validate_finding checks. Only after a durable CONFIRMED finding:<id> ledger result and a fresh complete similarity comparison may triage_vulnerability(status=approved) be called.",
      ].filter(Boolean).join("\n"),
      metadata: {
        updated: true,
        findingID: finding.id,
        status: "new",
        poc_saved: true,
        proof_hypothesis_key: proofHypothesisKey,
        evidence_refs: params.evidence_refs,
        target_reference: targetReference ?? null,
        target_reference_error: targetReferenceError ?? null,
      },
    }
  },
})
