import { index, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core"
import { SessionTable, VulnerabilityTable } from "../session/session.sql"
import { Timestamps } from "../storage/schema.sql"
import { ChainCandidateTable } from "./methodology.sql"

export type ChainFindingRelation = "depends_on" | "enables" | "contributes_to"

/**
 * Directed, session-scoped edges between real vulnerability findings, attached to
 * the chain hypothesis they support. Intel entry IDs remain separate from finding IDs.
 */
export const ChainFindingLinkTable = sqliteTable(
  "chain_finding_link",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    chain_candidate_id: text()
      .notNull()
      .references(() => ChainCandidateTable.id, { onDelete: "cascade" }),
    source_vulnerability_id: text()
      .notNull()
      .references(() => VulnerabilityTable.id, { onDelete: "cascade" }),
    target_vulnerability_id: text()
      .notNull()
      .references(() => VulnerabilityTable.id, { onDelete: "cascade" }),
    relation: text().$type<ChainFindingRelation>().notNull(),
    ...Timestamps,
  },
  (table) => [
    index("chain_finding_link_session_idx").on(table.session_id),
    index("chain_finding_link_chain_idx").on(table.chain_candidate_id),
    index("chain_finding_link_source_idx").on(table.source_vulnerability_id),
    index("chain_finding_link_target_idx").on(table.target_vulnerability_id),
    uniqueIndex("chain_finding_link_edge_idx").on(
      table.chain_candidate_id,
      table.source_vulnerability_id,
      table.target_vulnerability_id,
      table.relation,
    ),
  ],
)
