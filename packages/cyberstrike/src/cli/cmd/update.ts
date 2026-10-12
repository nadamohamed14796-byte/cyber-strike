import type { Argv } from "yargs"
import * as prompts from "@clack/prompts"
import { cmd } from "./cmd"
import { discoverResearch, learnResearchQueue } from "../../research/ingest"
import { ResearchQueue } from "../../research/queue"
import { ReportKnowledge } from "../../learning/report-knowledge"

function bounded(value: number | undefined, fallback: number, min: number, max: number) {
  const candidate = value === undefined || !Number.isFinite(value) ? fallback : Math.floor(value)
  return Math.max(min, Math.min(candidate, max))
}

/**
 * One resumable update cycle: discover public candidates, queue them durably,
 * learn a bounded batch, and report progress. Watch mode is explicit and opt-in.
 */
export const UpdateCommand = cmd({
  command: "update",
  describe: "discover and study public reports/writeups into globally shared research knowledge for every agent",
  builder: (yargs: Argv) =>
    yargs
      .option("pages", { type: "number", default: 10, describe: "maximum discovery pages per source for each cycle" })
      .option("depth", { type: "number", default: 2, describe: "maximum discovery depth" })
      .option("limit", { type: "number", default: 30, describe: "maximum queued items to study per cycle" })
      .option("watch", { type: "boolean", default: false, describe: "repeat bounded update cycles until interrupted" })
      .option("interval", { type: "number", default: 60, describe: "seconds between watch cycles" }),
  async handler(args) {
    const pages = bounded(args.pages, 10, 1, 1000)
    const depth = bounded(args.depth, 2, 0, 4)
    const limit = bounded(args.limit, 30, 1, 500)
    const interval = bounded(args.interval, 60, 5, 3600)

    prompts.intro("CyberStrike Research Update")
    let cycle = 0
    do {
      cycle++
      prompts.log.step("Cycle " + cycle + ": discovering public research")
      const discovery = await discoverResearch({ pages, depth })
      let candidates = 0
      let added = 0
      let blockedAuth = 0
      let errors = 0
      for (const result of discovery) {
        candidates += result.candidates
        added += result.added
        blockedAuth += result.blocked_auth
        errors += result.errors.length
        prompts.log.info(result.source + ": pages=" + result.pages + " candidates=" + result.candidates +
          " queued=" + result.added + " blocked_auth=" + result.blocked_auth)
        for (const error of result.errors) prompts.log.warn(error)
      }

      prompts.log.step("Studying queued research")
      const learned = await learnResearchQueue({ limit })
      for (const error of learned.errors) prompts.log.warn(error)

      const queueStats = ResearchQueue.stats()
      const knowledgeStats = ReportKnowledge.stats()
      prompts.log.info(
        "cycle=" + cycle +
          " discovered=" + candidates +
          " queued=" + added +
          " claimed=" + learned.claimed +
          " learned=" + learned.learned +
          " skipped=" + learned.skipped +
          " failed=" + learned.failed +
          " blocked_auth=" + (blockedAuth + learned.blocked_auth) +
          " discovery_errors=" + errors,
      )
      prompts.log.info(
        "queue: total=" + queueStats.total +
          " crawl_pages=" + queueStats.crawl_pages +
          " queued=" + queueStats.queued +
          " studying=" + queueStats.studying +
          " retry=" + queueStats.retry +
          " blocked_auth=" + queueStats.blocked_auth +
          " learned=" + queueStats.learned +
          " rejected=" + queueStats.rejected,
      )
      prompts.log.info(
        "knowledge: total=" + knowledgeStats.total +
          " external_research=" + knowledgeStats.external +
          " useful_or_confirmed=" + knowledgeStats.useful +
          " rejected_disproven_or_duplicate=" + knowledgeStats.rejected,
      )

      if (!args.watch) break
      await Bun.sleep(interval * 1000)
    } while (true)

    prompts.outro(args.watch ? "Research update worker stopped" : "Resumable research update cycle complete")
  },
})
