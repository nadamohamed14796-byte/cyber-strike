import z from "zod"
import { Chain } from "../methodology/chain"
import { Session } from "../session"
import { Tool } from "./tool"

export const ValidateChainTool = Tool.define("validate_chain", {
  description:
    "Record the result of testing a stored chain hypothesis. Use confirmed only after the combined attack path and impact were actually demonstrated, then create/report the combined vulnerability and complete validate_finding plus triage_vulnerability (approved) for that combined finding. Supply its ID as combined_finding_id. A confirmed verdict is blocked unless that finding's latest durable validation is confirmed and its triage status is approved. Use disproven only with concrete contradictory evidence; use inconclusive when evidence is insufficient. This tool records validation evidence; it does not run tests, create findings, approve findings, or bypass scope/policy controls.",
  parameters: z.object({
    chain_id: z.string().trim().min(1).describe("Chain candidate ID shown by methodology_status"),
    outcome: z.enum(["confirmed", "disproven", "inconclusive"]),
    evidence: z.string().trim().min(40).max(5000).describe("Concrete observed evidence for the combined path, including a baseline/control and demonstrated or disconfirming impact. Do not submit a planned test or speculative narrative."),
    combined_finding_id: z.string().trim().min(1).optional().describe("Required for confirmed: the combined vulnerability finding ID after its own validation and approved triage."),
  }),
  async execute(params, ctx) {
    const result = Chain.recordValidation({
      sessionID: Session.root(ctx.sessionID),
      chainID: params.chain_id,
      outcome: params.outcome,
      evidence: params.evidence,
      validatedBy: ctx.agent,
      combinedFindingID: params.combined_finding_id,
    })

    if (!result.ok) {
      const reasons: Record<typeof result.reason, string> = {
        chain_not_found: "The chain candidate does not exist in the current session.",
        chain_terminal: "This chain is already confirmed or disproven. Start a new validation only after a new chain hypothesis is created; no status was changed.",
        evidence_required: "Provide at least 40 characters of concrete observed evidence; no status was changed.",
        combined_finding_required: "A confirmed chain requires combined_finding_id. Report the combined finding, validate it, and explicitly approve it through triage first.",
        finding_not_found: "The combined finding ID does not refer to a finding in the current session.",
        finding_not_approved: "The combined finding must have status approved before the chain can be confirmed.",
        finding_validation_required: "The combined finding's latest validate_finding verdict must be confirmed before the chain can be confirmed.",
      }
      return {
        title: "Chain validation blocked",
        output: reasons[result.reason],
        metadata: { recorded: false, reason: result.reason, chainID: params.chain_id, outcome: params.outcome },
      }
    }

    return {
      title: `Chain ${result.chainID} → ${result.outcome}`,
      output: result.outcome === "confirmed"
        ? `Recorded confirmed chain ${result.chainID} with combined finding ${result.combinedFindingID}. The combined finding had to be independently validated and approved first.`
        : result.outcome === "disproven"
          ? `Recorded disproven chain ${result.chainID}. Individual findings remain unchanged; this verdict applies only to the combined-impact hypothesis.`
          : `Recorded inconclusive evidence for chain ${result.chainID}. It remains in testing and is not counted as a confirmed finding.`,
      metadata: {
        recorded: true,
        chainID: result.chainID,
        outcome: result.outcome,
        combinedFindingID: result.combinedFindingID,
      },
    }
  },
})
