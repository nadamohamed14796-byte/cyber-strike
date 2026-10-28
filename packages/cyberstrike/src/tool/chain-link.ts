import z from "zod"
import { Chain } from "../methodology/chain"
import type { ChainFindingRelation } from "../methodology/chain-finding-link.sql"
import { Session } from "../session"
import { Tool } from "./tool"

type ChainLinkToolMetadata = {
  linked: boolean
  created: boolean
  chainID: string
  sourceFindingID: string
  targetFindingID: string
  relation: ChainFindingRelation
  reason: string
}

function toolMetadata(value: ChainLinkToolMetadata): ChainLinkToolMetadata {
  return value
}

export const ChainLinkTool = Tool.define("chain_link", {
  description:
    "Record a directed relationship between two existing vulnerability findings under a detected chain candidate. Use the actual IDs returned by report_vulnerability and the chain candidate ID shown by methodology_status. Relations mean: depends_on (source depends on target), enables (source enables target), or contributes_to (source contributes to target). This records evidence organization only: it does not validate/approve either finding or confirm the chain. Findings must belong to the current session; duplicate and false-positive findings cannot be linked.",
  parameters: z.object({
    chain_id: z.string().trim().min(1).describe("Existing chain_candidate ID from the current session"),
    source_finding_id: z.string().trim().min(1).describe("Source vulnerability ID from report_vulnerability"),
    target_finding_id: z.string().trim().min(1).describe("Target vulnerability ID from report_vulnerability"),
    relation: z.enum(["depends_on", "enables", "contributes_to"]),
  }),
  async execute(params, ctx) {
    const result = Chain.linkFindings({
      sessionID: Session.root(ctx.sessionID),
      chainID: params.chain_id,
      sourceFindingID: params.source_finding_id,
      targetFindingID: params.target_finding_id,
      relation: params.relation,
    })
    if (!result.ok) {
      const reason = {
        chain_not_found: "The chain candidate was not found in the current session.",
        finding_not_found: "Both finding IDs must refer to findings in the current session.",
        inactive_finding: "Duplicate and false-positive findings cannot be linked into a chain.",
        self_link: "A finding cannot be linked to itself.",
        chain_terminal: "This chain is already confirmed or disproven and cannot accept new links.",
      }[result.reason]
      return {
        title: "Chain link not created",
        output: reason + " No relationship was written.",
        metadata: toolMetadata({
          linked: false,
          created: false,
          chainID: params.chain_id,
          sourceFindingID: params.source_finding_id,
          targetFindingID: params.target_finding_id,
          relation: params.relation,
          reason: result.reason,
        }),
      }
    }

    return {
      title: result.created ? "Chain finding relationship saved" : "Chain finding relationship already exists",
      output:
        `Saved ${result.link.sourceFindingID} --${result.link.relation}--> ${result.link.targetFindingID} under chain ${result.link.chainID}. This is a relationship record only; it does not approve findings or mark the chain confirmed.`,
      metadata: toolMetadata({
        linked: true,
        created: result.created,
        chainID: result.link.chainID,
        sourceFindingID: result.link.sourceFindingID,
        targetFindingID: result.link.targetFindingID,
        relation: result.link.relation,
        reason: "none",
      }),
    }
  },
})
