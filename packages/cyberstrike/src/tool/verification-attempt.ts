import z from "zod"
import { Tool } from "./tool"
import { Session } from "../session"
import { VerificationLedger } from "../session/verification-ledger"
import { VerificationAttempts as Policy } from "../methodology/verification-attempts"
import { redactTargetNoteSecrets } from "../target/redact"

function safeLedgerText(value: string | undefined): string | undefined {
  return value === undefined ? undefined : redactTargetNoteSecrets(value)
}

const RecordAction = z.object({
  action: z.literal("record"),
  hypothesis_key: z.string().min(1).describe("Stable key for one specific vulnerability hypothesis; reuse it across attempts for that same claim."),
  asset: z.string().min(1),
  endpoint: z.string().optional(),
  vulnerability_class: z.string().min(1),
  strategy_id: z.string().min(1).describe("Unique strategy name that describes the test angle, e.g. idor.owner-vs-non-owner."),
  variant_key: z.string().min(1).describe("Meaningful context/input variant; identical strategy+variant retries do not count."),
  rationale: z.string().min(1).describe("Why this is the next most informative test based on previous results."),
  result_summary: z.string().min(1).describe("What actually happened; never write a guessed result."),
  evidence_ref: z.string().optional().describe("Reference to stored request/response, artifact, or reproducible evidence. Required when valid_conditions=true so the result is evidence-backed."),
  valid_conditions: z.boolean().describe("True only when prerequisites, identity/session, scope, and test setup were valid."),
  decisive_result: z.enum(["none", "confirmed", "disproven"]).optional().default("none"),
  blocked_reason: z.string().optional(),
})
const StatusAction = z.object({
  action: z.literal("status"),
  hypothesis_key: z.string().min(1),
})
const Parameters = z.discriminatedUnion("action", [RecordAction, StatusAction])

type VerificationAttemptMetadata = {
  hypothesisKey: string
  attemptsUsed: number
  maxAttempts?: number
  outcome: Policy.Outcome
  remainingAttempts?: number
  canContinue?: boolean
  duplicate?: boolean
}

export const VerificationAttemptTool = Tool.define<typeof Parameters, VerificationAttemptMetadata>("verification_attempt", {
  description:
    "Mandatory durable ledger for adaptive vulnerability verification. Call action=record after EVERY meaningful verification attempt and before deciding a plausible candidate is a false positive. Reuse hypothesis_key for the same hypothesis. There is no arbitrary fixed hypothesis-count ceiling; exact strategy_id + variant_key retries are deduplicated. Only attempts with valid_conditions=true AND a durable evidence_ref are evidence-backed; missing evidence references are rejected for valid attempts, and duplicate retries do not consume the budget. Choose each next attempt based on previous evidence and vulnerability class. A failed HTTP request, 401/403/404/429, timeout, or WAF response alone NEVER proves false positive. Confirmation may stop early with decisive evidence_ref. A DISPROVEN outcome requires valid conditions and direct contradictory evidence_ref, not a minimum number of attempts. If unresolved, status remains INCONCLUSIVE / NEEDS REVIEW. action=status retrieves the durable ledger after restart.",
  parameters: Parameters,
  async execute(params, ctx) {
    const sessionID = Session.root(ctx.sessionID)
    const hypothesisKey = redactTargetNoteSecrets(params.hypothesis_key)
    if (params.action === "record" && params.valid_conditions && !params.evidence_ref?.trim()) {
      return {
        title: "Verification attempt rejected: evidence reference required",
        output: "No attempt was recorded. valid_conditions=true requires evidence_ref pointing to a stored request/response, artifact, or reproducible observation. If evidence is not available, record valid_conditions=false and keep the hypothesis inconclusive until evidence is preserved.",
        metadata: { hypothesisKey, attemptsUsed: 0,  outcome: "inconclusive", canContinue: true },
      }
    }
    if (params.action === "status") {
      const attempts = VerificationLedger.list({ sessionID, hypothesisKey })
      const uniqueAttempts = Policy.uniqueAttempts(attempts)
      const attemptsUsed = uniqueAttempts.filter((attempt) => Policy.isEvidenceBackedValidAttempt(attempt)).length
      const last = attempts[attempts.length - 1]
      const outcome = last?.outcome ?? "inconclusive"
      const lines = attempts.map((a, i) =>
        `${i + 1}. [${redactTargetNoteSecrets(a.strategyID)} / ${redactTargetNoteSecrets(a.variantKey)}] valid=${a.validConditions} — why: ${redactTargetNoteSecrets(a.rationale)} — result: ${redactTargetNoteSecrets(a.resultSummary)}${a.evidenceRef ? ` (evidence: ${redactTargetNoteSecrets(a.evidenceRef)})` : ""}`,
      )
      return {
        title: `Verification: ${attemptsUsed} evidence-backed attempts — ${outcome.toUpperCase()}`,
        output: attempts.length
          ? `Hypothesis: ${hypothesisKey}\nOutcome: ${outcome}\nValid evidence-backed attempts: ${attemptsUsed}\nRecorded distinct attempts: ${uniqueAttempts.length}\n${lines.join("\n")}`
          : `No verification attempts recorded for hypothesis ${hypothesisKey}.`,
        metadata: {
          hypothesisKey,
          attemptsUsed,
          
          outcome,
          
          canContinue: outcome === "inconclusive",
          duplicate: false,
        },
      }
    }

    const result = VerificationLedger.record({
      sessionID,
      hypothesisKey,
      asset: redactTargetNoteSecrets(params.asset),
      endpoint: safeLedgerText(params.endpoint),
      vulnerabilityClass: redactTargetNoteSecrets(params.vulnerability_class),
      attempt: {
        strategyID: redactTargetNoteSecrets(params.strategy_id),
        variantKey: redactTargetNoteSecrets(params.variant_key),
        rationale: redactTargetNoteSecrets(params.rationale),
        resultSummary: redactTargetNoteSecrets(params.blocked_reason
          ? `${params.result_summary} [Blocked: ${params.blocked_reason}]`
          : params.result_summary),
        evidenceRef: safeLedgerText(params.evidence_ref),
        validConditions: params.valid_conditions,
      },
      decisiveResult: params.decisive_result,
      blockedReason: safeLedgerText(params.blocked_reason),
    })
    const d = result.decision
    const status = d.outcome.toUpperCase()
    const next = d.canContinue ? "Choose a different evidence-driven strategy and record its result." :
      d.outcome === "inconclusive" ? "Stop testing; preserve as NEEDS REVIEW, never false positive based on attempt count." :
      "Decisive evidence recorded; stop this hypothesis and preserve the evidence."
    return {
      title: `Verification (${d.attemptsUsed} evidence-backed attempts): ${status}`,
      output: [
        `Hypothesis: ${hypothesisKey}`,
        `Outcome: ${status}`,
        `Evidence-backed attempts recorded: ${d.attemptsUsed}`,
        `No fixed hypothesis-count ceiling; duplicate strategy/variant pairs are deduplicated.`,
        `Duplicate attempt: ${result.duplicate ? "yes — not counted again" : "no"}`,
        `Reason: ${d.reason}`,
        next,
      ].join("\n"),
      metadata: {
        hypothesisKey: params.hypothesis_key,
        attemptsUsed: d.attemptsUsed,
        
        
        outcome: d.outcome,
        canContinue: d.canContinue,
        duplicate: result.duplicate,
      },
    }
  },
})
