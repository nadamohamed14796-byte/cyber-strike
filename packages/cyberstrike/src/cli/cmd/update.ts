import type { Argv } from "yargs"
import * as prompts from "@clack/prompts"
import { cmd } from "./cmd"
import { discoverResearch, learnResearchQueue, retryAuthenticatedResearch } from "../../research/ingest"
import { RESEARCH_SOURCES } from "../../research/sources"
import { ResearchQueue } from "../../research/queue"
import { ReportKnowledge } from "../../learning/report-knowledge"

/**
 * One resumable research update. Page windows grow until each source is exhausted
 * or has a recorded blocker; queue processing continues in batches until no work
 * remains claimable. Batch sizes are implementation details, never total-work caps.
 */
export const UpdateCommand = cmd({
  command: "update",
  describe: "heuristic public-research sync (does not invoke active-model study; use /update for model-led research)",
  builder: (yargs: Argv) =>
    yargs
      .option("print-prompt", { type: "boolean", default: false, describe: "print the canonical copyable research update agent prompt without running a crawl" })
      .option("watch", { type: "boolean", default: false, describe: "repeat exhaustive update cycles until interrupted" })
      .option("interval", { type: "number", default: 60, describe: "seconds between watch cycles" }),
  async handler(args) {
    if (args.printPrompt) {
      const promptFile = Bun.file(new URL("../../../docs/research-update-agent-prompt.md", import.meta.url))
      if (!(await promptFile.exists())) {
        throw new Error("Canonical research prompt file is missing from this installation: " + promptFile.name)
      }
      console.log(await promptFile.text())
      return
    }

    const interval = Number.isFinite(args.interval)
      ? Math.max(5, Math.floor(args.interval))
      : 60

    prompts.intro("CyberStrike Heuristic Research Sync (not active-model /update)")
    let cycle = 0
    do {
      cycle++
      let totalCandidates = 0
      let totalQueued = 0
      let totalPages = 0
      let totalLearned = 0
      let totalSkipped = 0
      let totalFailed = 0
      let totalBlockedAuth = 0
      let totalDiscoveryErrors = 0
      const incompleteSources: Array<{ source: string; reason: string }> = []

      prompts.log.step("Cycle " + cycle + ": resuming authentication-blocked research")
      while (true) {
        const resumed = await retryAuthenticatedResearch({ limit: 500 })
        if (resumed === 0) break
        prompts.log.info("auth-blocked research resumed=" + resumed)
      }

      for (const configuredSource of RESEARCH_SOURCES) {
        prompts.log.step("Discovering source: " + configuredSource.id)
        let pageWindow = 20
        let sourceFinished = false

        while (!sourceFinished) {
          let result: Awaited<ReturnType<typeof discoverResearch>>[number] | undefined
          try {
            const pass = await discoverResearch({
              sourceID: configuredSource.id,
              pages: pageWindow,
              depth: Number.MAX_SAFE_INTEGER,
            })
            result = pass[0]
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            incompleteSources.push({ source: configuredSource.id, reason: "discovery call failed: " + message })
            prompts.log.warn(configuredSource.id + ": discovery call failed: " + message)
            break
          }

          if (!result) {
            incompleteSources.push({ source: configuredSource.id, reason: "discovery returned no source result" })
            break
          }

          totalPages += result.pages
          totalCandidates += result.candidates
          totalQueued += result.added
          totalBlockedAuth += result.blocked_auth
          totalDiscoveryErrors += result.error_count

          prompts.log.info(
            result.source + ": requested_page_window=" + pageWindow +
              " processed_pages=" + result.pages +
              " candidates=" + result.candidates +
              " queued_new=" + result.added +
              " blocked_auth=" + result.blocked_auth +
              " errors=" + result.error_count,
          )
          for (const error of result.errors) prompts.log.warn(error)

          // Study all claimable work after every discovery pass so the durable
          // queue does not grow indefinitely before processing starts.
          while (true) {
            const batch = await learnResearchQueue({ limit: 500, sourceID: configuredSource.id })
            totalLearned += batch.learned
            totalSkipped += batch.skipped
            totalFailed += batch.failed
            totalBlockedAuth += batch.blocked_auth
            for (const error of batch.errors) prompts.log.warn(error)
            if (batch.claimed === 0) break
          }

          const sourceQueue = ResearchQueue.stats(configuredSource.id)
          const hasRecordedBlockers =
            result.error_count > 0 ||
            result.blocked_auth > 0 ||
            sourceQueue.crawl_page_errors > 0 ||
            sourceQueue.crawl_page_auth_blocked > 0 ||
            sourceQueue.retry > 0 ||
            sourceQueue.studying > 0

          if (hasRecordedBlockers) {
            const reasons = [
              result.error_count > 0 ? "discovery errors=" + result.error_count : "",
              result.blocked_auth > 0 || sourceQueue.crawl_page_auth_blocked > 0 ? "authentication required" : "",
              sourceQueue.crawl_page_errors > 0 ? "stored crawl-page errors=" + sourceQueue.crawl_page_errors : "",
              sourceQueue.retry > 0 ? "retry queue=" + sourceQueue.retry : "",
              sourceQueue.studying > 0 ? "active/stale study leases=" + sourceQueue.studying : "",
            ].filter(Boolean).join(", ")
            incompleteSources.push({ source: configuredSource.id, reason: reasons || "unresolved queue state" })
            prompts.log.warn(configuredSource.id + ": incomplete; " + (reasons || "unresolved queue state"))
            sourceFinished = true
            continue
          }

          // If the requested window was exhausted, expand it and continue. There is
          // deliberately no fixed maximum page count or crawl depth.
          if (result.pages >= pageWindow) {
            const nextWindow = pageWindow * 2
            if (!Number.isSafeInteger(nextWindow) || nextWindow <= pageWindow) {
              incompleteSources.push({
                source: configuredSource.id,
                reason: "runtime integer range exhausted before source pagination could be proven complete",
              })
              sourceFinished = true
              continue
            }
            pageWindow = nextWindow
            continue
          }

          sourceFinished = true
        }
      }

      // Final global drain catches legacy or concurrent work that was not tied to
      // the source-specific pass above. Each call is a bounded batch; total work is not.
      while (true) {
        const batch = await learnResearchQueue({ limit: 500 })
        totalLearned += batch.learned
        totalSkipped += batch.skipped
        totalFailed += batch.failed
        totalBlockedAuth += batch.blocked_auth
        for (const error of batch.errors) prompts.log.warn(error)
        if (batch.claimed === 0) break
      }

      const queueStats = ResearchQueue.stats()
      const knowledgeStats = ReportKnowledge.stats()
      prompts.log.info(
        "cycle=" + cycle +
          " page_visits_across_passes=" + totalPages +
          " discovered_candidates=" + totalCandidates +
          " queued_new=" + totalQueued +
          " learned=" + totalLearned +
          " skipped=" + totalSkipped +
          " failed=" + totalFailed +
          " blocked_auth=" + totalBlockedAuth +
          " discovery_errors=" + totalDiscoveryErrors,
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
          " rejected_disproven_or_duplicate=" + knowledgeStats.rejected +
          " external_references_used=" + knowledgeStats.externalReferencesUsed +
          " external_reference_usefulness_events=" + knowledgeStats.externalReferenceUsefulnessEvents,
      )

      if (incompleteSources.length) {
        prompts.log.warn("Update is PARTIAL; unresolved sources:")
        for (const item of incompleteSources) prompts.log.warn(item.source + ": " + item.reason)
      } else {
        prompts.log.success("All configured source discovery windows exhausted and claimable research drained.")
      }

      if (!args.watch) break
      await Bun.sleep(interval * 1000)
    } while (true)

    prompts.outro(args.watch ? "Heuristic research worker stopped; use /update for active-model study" : "Heuristic sync finished; this CLI path does not invoke active-model research_study. Use /update in the interactive agent for model-led study.")
  },
})
