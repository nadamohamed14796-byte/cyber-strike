import z from "zod"
import { Tool } from "./tool"
import { Session } from "../session"
import { VerificationLedger } from "../session/verification-ledger"
import { VerificationAttempts as Policy } from "../methodology/verification-attempts"

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
  evidence_ref: z.string().optional().describe("Reference to stored request/response, artifact, or reproducible evidence."),
  valid_conditions: z.boolean().describe("True only when prerequisites, identity/session, scope, and test setup were valid."),
  decisive_result: z.enum(["none", "confirmed", "disproven"]).optional().default("none"),
  blocked_reason: z.string().optional(),
})
const StatusAction = z.object({
  action: z.literal("status"),
  hypothesis_key: z.string().min(1),
})
const Parameters = z.discriminatedUnion("action", [RecordAction, StatusAction])

export const VerificationAttemptTool = Tool.define("verification_attempt", {
  description:
    "Mandatory durable ledger for adaptive vulnerability verification. Call action=record after EVERY meaningful verification attempt and before deciding a plausible candidate is a false positive. Reuse hypothesis_key for the same hypothesis. Up to 20 distinct strategy_id + variant_key combinations per hypothesis; duplicate retries do not consume budget. Choose each next attempt based on previous evidence and vulnerability class. A failed HTTP request, 401/403/404/429, timeout, WAF response, or exhausted budget alone NEVER proves false positive. Use decisive_result=confirmed only with decisive evidence_ref. Use decisive_result=disproven only with direct contradictory evidence_ref and valid_conditions=true. If unresolved at 20, status is INCONCLUSIVE/NEEDS REVIEW. action=status retrieves the durable ledger after restart.",
  parameters: Parameters,
  async execute(params, ctx) {
    const sessionID = Session.root(ctx.sessionID)
    if (params.action === "status") {
      const attempts = VerificationLedger.list({ sessionID, hypothesisKey: params.hypothesis_key })
      const last = attempts[attempts.length - 1]
      const outcome = last?.outcome ?? "inconclusive"
      const lines = attempts.map((a, i) =>
        `${i + 1}. [${a.strategyID} / ${a.variantKey}] valid=${a.validConditions} — ${a.resultSummary}${a.evidenceRef ? ` (evidence: ${a.evidenceRef})` : ""}`,
      )
      return {
        title: `Verification: ${attempts.length}/${Policy.MAX_ATTEMPTS} — ${outcome.toUpperCase()}`,
        output: attempts.length
          ? `Hypothesis: ${params.hypothesis_key}\nOutcome: ${outcome}\nAttempts: ${attempts.length}/${Policy.MAX_ATTEMPTS}\n${lines.join("\n")}${attempts.length >= Policy.MAX_ATTEMPTS && outcome === "inconclusive" ? "\nBudget exhausted: preserve as INCONCLUSIVE / NEEDS REVIEW; not a false positive." : ""}`
          : `No verification attempts recorded for hypothesis ${params.hypothesis_key}.`,
        metadata: { hypothesisKey: params.hypothesis_key, attemptsUsed: attempts.length, maxAttempts: Policy.MAX_ATTEMPTS, outcome },
      }
    }

    const result = VerificationLedger.record({
      sessionID,
      hypothesisKey: params.hypothesis_key,
      asset: params.asset,
      endpoint: params.endpoint,
      vulnerabilityClass: params.vulnerability_class,
      attempt: {
        strategyID: params.strategy_id,
        variantKey: params.variant_key,
        rationale: params.rationale,
        resultSummary: params.result_summary,
        evidenceRef: params.evidence_ref,
        validConditions: params.valid_conditions,
      },
      decisiveResult: params.decisive_result,
      blockedReason: params.blocked_reason,
    })
    const d = result.decision
    const status = d.outcome.toUpperCase()
    const next = d.canContinue ? "Choose a different evidence-driven strategy and record its result." :
      d.outcome === "inconclusive" ? "Stop testing; preserve as NEEDS REVIEW, never false positive based on attempt count." :
      "Decisive evidence recorded; stop this hypothesis and preserve the evidence."
    return {
      title: `Verification ${d.attemptsUsed}/${Policy.MAX_ATTEMPTS}: ${status}`,
      output: [
        `Hypothesis: ${params.hypothesis_key}`,
        `Outcome: ${status}`,
        `Attempts used: ${d.attemptsUsed}/${Policy.MAX_ATTEMPTS}`,
        `Remaining: ${d.remainingAttempts}`,
        `Duplicate attempt: ${result.duplicate ? "yes — not counted again" : "no"}`,
        `Reason: ${d.reason}`,
        next,
      ].join("\n"),
      metadata: { hypothesisKey: params.hypothesis_key, attemptsUsed: d.attemptsUsed, remainingAttempts: d.remainingAttempts, outcome: d.outcome, canContinue: d.canContinue, duplicate: result.duplicate },
    }
  },
})
