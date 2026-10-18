import z from "zod"
import { Tool } from "./tool"
import { FalsePositiveKnowledge } from "../methodology/false-positive-knowledge"

const Parameters = z.object({
  title: z.string().trim().min(1).max(240).describe("Candidate finding title or concise observed signal"),
  description: z.string().trim().min(1).max(3000).describe("Current evidence and suspected vulnerability class; do not include credentials or raw tokens"),
  endpoint: z.string().trim().max(1000).optional().describe("Affected endpoint or normalized path, if known"),
  offset: z.number().int().min(0).default(0).describe("Pagination offset; continue from next_offset until has_more is false"),
  page_size: z.number().int().min(1).default(10).describe("Number of matching records returned in this response; no application-defined maximum, continue with further pages"),
})

export const FalsePositiveMemoryTool = Tool.define<typeof Parameters, Tool.Metadata>("false_positive_memory", {
  description: [
    "Search the persistent cross-target SQLite memory of previously validated false-positive patterns.",
    "Use when a concrete finding hypothesis or suspicious signal appears, before spending time repeating known benign explanations; query again only when the hypothesis or evidence materially changes.",
    "Results are advisory examples, not an allow/deny list. A similar historical false positive must never automatically suppress a new finding. Compare its exact preconditions and benign explanation against current evidence and still perform the ten-check validation.",
    "Results are paginated for response delivery only. If has_more is true, continue with offset=next_offset until the matching memory is exhausted; there is no fixed total-result ceiling.",
    "The database stores normalized patterns and sanitized short explanations, not raw HTTP traffic, tokens, or PoCs.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params) {
    try {
      const page = FalsePositiveKnowledge.similar({
        title: params.title,
        description: params.description,
        endpoint: params.endpoint,
        offset: params.offset ?? 0,
        pageSize: params.page_size ?? 10,
      })
      const matches = page.matches
      if (!matches.length) {
        return {
          title: "No matching false-positive memory",
          output: page.total === 0
            ? "No relevant historical false-positive pattern was found. This does not prove the finding is real; continue controlled testing and evidence-based validation."
            : "No matching records on this page. Reset offset to 0 or inspect the total matching record count.",
          metadata: { matches: 0, total: page.total, offset: page.offset, next_offset: page.nextOffset, has_more: page.hasMore },
        }
      }
      return {
        title: "Historical false-positive patterns: " + matches.length + " of " + page.total,
        output: [
          "These are historical comparison clues only. Do not reject or downgrade the current finding from similarity alone.",
          "Page offset: " + page.offset + "; returned: " + matches.length + "; total matching records: " + page.total + ". " +
            (page.hasMore ? "Continue with offset=" + page.nextOffset + " to inspect the remaining matches." : "All matching records have been returned."),
          ...matches.map((item, index) => [
            (index + 1) + ". " + item.titlePattern + " [" + item.vulnerabilityClass + "]",
            "Similarity: " + item.similarity + "%; repeated observations: " + item.occurrences + "; confidence label: " + item.confidence + "/100 (heuristic, not probability).",
            "Endpoint pattern: " + (item.endpointPattern ?? "not recorded"),
            "Contradictory checks: " + item.failedCheckIDs.join(", "),
            "Prior benign explanation: " + item.benignExplanation,
            "Prior evidence summary: " + item.evidenceSummary,
            "Compare the old case's preconditions and control results with the current target. Revalidate independently.",
          ].join("\n")).join("\n\n"),
        ].join("\n\n"),
        metadata: { matches: matches.length, total: page.total, offset: page.offset, next_offset: page.nextOffset, has_more: page.hasMore, records: matches.map(({ id, similarity }) => ({ id, similarity })) },
      }
    } catch (error) {
      return {
        title: "False-positive memory unavailable",
        output: error instanceof Error ? error.message : String(error),
        metadata: { error: true },
      }
    }
  },
})
