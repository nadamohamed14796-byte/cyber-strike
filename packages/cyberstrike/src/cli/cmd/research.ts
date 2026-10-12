import * as prompts from "@clack/prompts"
import { cmd } from "./cmd"
import { ReportKnowledge } from "../../learning/report-knowledge"
import { RESEARCH_SOURCES } from "../../research/sources"
import { discoverResearch, learnResearchQueue, syncResearch } from "../../research/ingest"
import { ResearchQueue } from "../../research/queue"

function knowledgeScoreLabel(row: {
  confidence: number
  source_kind: string
  status: string
  metadata?: Record<string, unknown> | null
}) {
  if (row.source_kind === "external_report" && row.status === "observed") {
    const trust = row.metadata?.source_trust
    const value =
      typeof trust === "number" && Number.isFinite(trust)
        ? String(Math.max(0, Math.min(100, Math.round(trust)))) + "%"
        : "unknown"
    return "source-trust=" + value + " (unverified)"
  }
  return "confidence=" + row.confidence + "%"
}

export const ResearchCommand = cmd({
  command: "research",
  describe: "discover, study, and search public security research persisted in SQLite",
  builder: (yargs) =>
    yargs
      .command({
        command: "sources",
        describe: "list configured public research sources",
        async handler() {
          for (const source of RESEARCH_SOURCES) console.log(source.id + " — " + source.name)
        },
      })
      .command({
        command: "sync [source]",
        describe: "crawl configured research sources and learn from public security material",
        builder: (yargs) =>
          yargs
            .positional("source", { type: "string" })
            .option("limit", {
              type: "number",
              default: 50,
              describe: "maximum new knowledge records per source",
            })
            .option("pages", {
              type: "number",
              default: 250,
              describe: "maximum pages crawled per source",
            })
            .option("depth", {
              type: "number",
              default: 2,
              describe: "maximum crawl depth from each seed URL",
            })
            .option("deep", {
              type: "boolean",
              default: false,
              describe: "deep preset: 200 new records, 750 pages, depth 3",
            })
            .option("all", {
              type: "boolean",
              default: false,
              describe: "exhaust the discovered public queue up to the page/depth budgets",
            }),
        async handler(args) {
          prompts.intro("CyberStrike Research Learning")
          const deep = Boolean(args.deep)
          const exhaustive = Boolean(args.all)
          const results = await syncResearch({
            sourceID: args.source,
            limit: deep ? 200 : args.limit,
            pages: exhaustive ? 1000 : deep ? 750 : args.pages,
            depth: exhaustive ? 4 : deep ? 3 : args.depth,
            all: exhaustive,
          })
          for (const result of results) {
            prompts.log.info(
              result.source +
                ": fetched=" +
                result.fetched +
                " learned=" +
                result.learned +
                " skipped=" +
                result.skipped +
                " failed=" +
                result.failed +
                " pages=" +
                result.pages_crawled +
                " candidates=" +
                result.candidates_discovered,
            )
            for (const error of result.error_samples) prompts.log.warn(error)
          }
          prompts.outro(exhaustive ? "Exhaustive research sync complete" : "Research sync complete")
        },
      })
      .command({
        command: "discover [source]",
        describe: "discover public research URLs and persist them to the durable queue",
        builder: (yargs) =>
          yargs
            .positional("source", { type: "string" })
            .option("pages", { type: "number", default: 100, describe: "maximum pages visited per source" })
            .option("depth", { type: "number", default: 2, describe: "maximum discovery depth" })
            .option("watch", { type: "boolean", default: false, describe: "repeat discovery until interrupted" })
            .option("interval", { type: "number", default: 300, describe: "seconds between watch cycles" }),
        async handler(args) {
          prompts.intro("CyberStrike Research Discovery Worker")
          do {
            const results = await discoverResearch({ sourceID: args.source, pages: args.pages, depth: args.depth })
            for (const result of results) {
              prompts.log.info(
                result.source +
                  ": pages=" +
                  result.pages +
                  " candidates=" +
                  result.candidates +
                  " added=" +
                  result.added,
              )
              for (const error of result.errors) prompts.log.warn(error)
            }
            if (!args.watch) break
            await Bun.sleep(Math.max(5, args.interval) * 1000)
          } while (true)
        },
      })
      .command({
        command: "learn",
        describe: "study queued public reports and add research notes to knowledge",
        builder: (yargs) =>
          yargs
            .option("limit", { type: "number", default: 50, describe: "maximum queue items processed per cycle" })
            .option("worker", { type: "string", describe: "worker label for queue leases" })
            .option("watch", {
              type: "boolean",
              default: false,
              describe: "keep processing new queue items until interrupted",
            })
            .option("interval", { type: "number", default: 10, describe: "seconds between queue checks when idle" }),
        async handler(args) {
          prompts.intro("CyberStrike Research Learning Worker")
          do {
            const result = await learnResearchQueue({ limit: args.limit, workerID: args.worker })
            prompts.log.info(
              "worker=" +
                result.worker +
                " claimed=" +
                result.claimed +
                " learned=" +
                result.learned +
                " skipped=" +
                result.skipped +
                " failed=" +
                result.failed,
            )
            for (const error of result.errors) prompts.log.warn(error)
            if (!args.watch) break
            if (result.claimed === 0 || result.failed > 0) await Bun.sleep(Math.max(2, args.interval) * 1000)
          } while (true)
        },
      })
      .command({
        command: "queue-stats",
        describe: "show persistent research queue counts by status",
        async handler() {
          const stats = ResearchQueue.stats()
          for (const [status, count] of Object.entries(stats)) console.log(status + "=" + count)
        },
      })
      .command({
        command: "queue-pending",
        describe: "list pending research queue items with stable report IDs",
        builder: (yargs) => yargs.option("limit", { type: "number", default: 50 }),
        async handler(args) {
          const rows = ResearchQueue.pending(args.limit)
          for (const row of rows) {
            console.log(
              row.public_id + " [" + row.status + "] " + row.source_id + " — " + (row.title ?? row.source_url),
            )
          }
          console.log("pending=" + rows.length)
        },
      })
      .command({
        command: "search <query>",
        describe: "search learned research knowledge",
        builder: (yargs) =>
          yargs
            .positional("query", { type: "string", demandOption: true })
            .option("limit", { type: "number", default: 20 }),
        async handler(args) {
          const rows = ReportKnowledge.search({ query: args.query, sourceKind: "external_report", limit: args.limit })
          for (const row of rows)
            console.log(
              knowledgeScoreLabel(row) +
                " " +
                (row.vulnerability_class ?? "unknown") +
                " — " +
                row.title +
                " — " +
                (row.source_url ?? "local"),
            )
        },
      })
      .command({
        command: "recommend <query>",
        describe: "show relevant research references; public imports are unverified until independently validated",
        builder: (yargs) =>
          yargs
            .positional("query", { type: "string", demandOption: true })
            .option("class", { type: "string" })
            .option("cwe", { type: "string" })
            .option("limit", { type: "number", default: 6 }),
        async handler(args) {
          const rows = ReportKnowledge.recommendations({
            signal: args.query,
            vulnerabilityClass: args.class,
            cweID: args.cwe,
            sourceKind: "external_report",
            limit: args.limit,
          })
          for (const row of rows) {
            console.log(
              knowledgeScoreLabel(row) +
                " " +
                (row.vulnerability_class ?? "unknown") +
                " — " +
                row.title +
                " — " +
                (row.lesson ?? "no lesson") +
                " — " +
                (row.source_url ?? "local"),
            )
          }
        },
      })
      .command({
        command: "stats",
        describe: "show research knowledge database statistics",
        async handler() {
          const stats = ReportKnowledge.stats()
          console.log("knowledge_total=" + stats.total)
          console.log("external_research=" + stats.external)
          console.log("useful_or_confirmed=" + stats.useful)
          console.log("rejected_disproven_or_duplicate=" + stats.rejected)
        },
      })
      .demandCommand(),
  async handler() {},
})
