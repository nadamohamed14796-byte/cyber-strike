import * as prompts from "@clack/prompts"
import { cmd } from "./cmd"
import { ReportKnowledge } from "../../learning/report-knowledge"
import { RESEARCH_LEARNING_VERSION, RESEARCH_SOURCES } from "../../research/sources"
import { classifyResearchTopic, discoverResearch, extractResearchDetails, learnResearchQueue, retryAuthenticatedResearch } from "../../research/ingest"
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
          for (const source of RESEARCH_SOURCES) {
            const suffix = source.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_")
            const cookieEnv = "CYBERSTRIKE_RESEARCH_COOKIE_" + suffix
            const authEnv = "CYBERSTRIKE_RESEARCH_AUTHORIZATION_" + suffix
            const configured = Boolean(process.env[cookieEnv]?.trim() || process.env[authEnv]?.trim())
            console.log(source.id + " — " + source.name + " — session=" + (configured ? "configured" : "not-configured"))
            if (!configured) console.log("  optional auth: " + cookieEnv + " or " + authEnv)
          }
        },
      })
      .command({
        command: "sync [source]",
        describe: "exhaustively discover and learn from all accessible public security research",
        builder: (yargs) => yargs.positional("source", { type: "string" }),
        async handler(args) {
          prompts.intro("CyberStrike Exhaustive Research Learning")
          const sources = args.source
            ? RESEARCH_SOURCES.filter((source) => source.id === args.source)
            : RESEARCH_SOURCES
          if (!sources.length) throw new Error("unknown research source: " + args.source)

          const totals = { pages: 0, candidates: 0, queued: 0, learned: 0, skipped: 0, failed: 0, blockedAuth: 0, errors: 0 }
          const incomplete: Array<{ source: string; reason: string }> = []

          for (const source of sources) {
            prompts.log.step("Discovering source: " + source.id)
            while (true) {
              const resumed = await retryAuthenticatedResearch({ sourceID: source.id, limit: 500 })
              if (resumed === 0) break
              prompts.log.info(source.id + ": auth-blocked rows resumed=" + resumed)
            }

            let pageWindow = 20
            let finished = false
            while (!finished) {
              let result: Awaited<ReturnType<typeof discoverResearch>>[number] | undefined
              try {
                result = (await discoverResearch({
                  sourceID: source.id,
                  pages: pageWindow,
                  depth: Number.MAX_SAFE_INTEGER,
                }))[0]
              } catch (error) {
                const message = error instanceof Error ? error.message : String(error)
                incomplete.push({ source: source.id, reason: "discovery call failed: " + message })
                prompts.log.warn(source.id + ": discovery call failed: " + message)
                break
              }
              if (!result) {
                incomplete.push({ source: source.id, reason: "discovery returned no result" })
                break
              }

              totals.pages += result.pages
              totals.candidates += result.candidates
              totals.queued += result.added
              totals.blockedAuth += result.blocked_auth
              totals.errors += result.error_count
              prompts.log.info(source.id + ": processed_pages=" + result.pages +
                " page_window=" + pageWindow + " candidates=" + result.candidates +
                " queued_new=" + result.added + " blocked_auth=" + result.blocked_auth +
                " errors=" + result.error_count)
              for (const error of result.errors) prompts.log.warn(error)

              while (true) {
                const batch = await learnResearchQueue({ limit: 500, sourceID: source.id })
                totals.learned += batch.learned
                totals.skipped += batch.skipped
                totals.failed += batch.failed
                totals.blockedAuth += batch.blocked_auth
                for (const error of batch.errors) prompts.log.warn(error)
                if (batch.claimed === 0) break
              }

              const stats = ResearchQueue.stats(source.id)
              const blocked =
                result.error_count > 0 ||
                result.blocked_auth > 0 ||
                stats.crawl_page_errors > 0 ||
                stats.crawl_page_auth_blocked > 0 ||
                stats.blocked_auth > 0 ||
                stats.retry > 0 ||
                stats.studying > 0
              if (blocked) {
                const reason = [
                  result.error_count ? "discovery errors=" + result.error_count : "",
                  result.blocked_auth || stats.blocked_auth || stats.crawl_page_auth_blocked ? "authentication required" : "",
                  stats.crawl_page_errors ? "crawl-page errors=" + stats.crawl_page_errors : "",
                  stats.retry ? "retry queue=" + stats.retry : "",
                  stats.studying ? "active/stale study leases=" + stats.studying : "",
                ].filter(Boolean).join(", ") || "unresolved queue state"
                incomplete.push({ source: source.id, reason })
                prompts.log.warn(source.id + ": partial: " + reason)
                finished = true
                continue
              }

              if (result.pages >= pageWindow) {
                const nextWindow = pageWindow * 2
                if (!Number.isSafeInteger(nextWindow) || nextWindow <= pageWindow) {
                  incomplete.push({ source: source.id, reason: "runtime integer range exhausted before pagination was proven complete" })
                  finished = true
                } else {
                  pageWindow = nextWindow
                }
                continue
              }
              finished = true
            }
          }

          // Final global drain covers legacy rows and any queue work not tied to the
          // selected source's discovery pass. The batch is bounded; total work is not.
          while (true) {
            const batch = await learnResearchQueue({ limit: 500, sourceID: args.source })
            totals.learned += batch.learned
            totals.skipped += batch.skipped
            totals.failed += batch.failed
            totals.blockedAuth += batch.blocked_auth
            for (const error of batch.errors) prompts.log.warn(error)
            if (batch.claimed === 0) break
          }

          const queue = ResearchQueue.stats(args.source)
          const knowledge = ReportKnowledge.stats()
          prompts.log.info("Totals: processed_pages=" + totals.pages + " candidates=" + totals.candidates +
            " queued_new=" + totals.queued + " learned=" + totals.learned + " skipped=" + totals.skipped +
            " failed=" + totals.failed + " blocked_auth=" + totals.blockedAuth + " discovery_errors=" + totals.errors)
          prompts.log.info("Queue: " + JSON.stringify(queue))
          prompts.log.info("Knowledge: " + JSON.stringify(knowledge))
          if (incomplete.length) {
            prompts.log.warn("Research sync is PARTIAL; unresolved sources:")
            for (const item of incomplete) prompts.log.warn(item.source + ": " + item.reason)
          } else {
            prompts.log.success("All selected sources exhausted their accessible discovery frontier.")
          }
          prompts.outro("Research sync finished; inspect the source ledger for any blockers")
        },
      })
      .command({
        command: "discover [source]",
        describe: "exhaustively discover public research URLs and persist them to the durable queue",
        builder: (yargs) =>
          yargs
            .positional("source", { type: "string" })
            .option("watch", { type: "boolean", default: false, describe: "repeat exhaustive discovery until interrupted" })
            .option("interval", { type: "number", default: 300, describe: "seconds between watch cycles" }),
        async handler(args) {
          prompts.intro("CyberStrike Exhaustive Research Discovery")
          do {
            const sources = args.source
              ? RESEARCH_SOURCES.filter((source) => source.id === args.source)
              : RESEARCH_SOURCES
            if (!sources.length) throw new Error("unknown research source: " + args.source)
            const incomplete: Array<{ source: string; reason: string }> = []

            for (const source of sources) {
              while (true) {
                const resumed = await retryAuthenticatedResearch({ sourceID: source.id, limit: 500 })
                if (resumed === 0) break
              }
              let pageWindow = 20
              let finished = false
              while (!finished) {
                let result: Awaited<ReturnType<typeof discoverResearch>>[number] | undefined
                try {
                  result = (await discoverResearch({
                    sourceID: source.id,
                    pages: pageWindow,
                    depth: Number.MAX_SAFE_INTEGER,
                  }))[0]
                } catch (error) {
                  const message = error instanceof Error ? error.message : String(error)
                  incomplete.push({ source: source.id, reason: "discovery call failed: " + message })
                  break
                }
                if (!result) {
                  incomplete.push({ source: source.id, reason: "discovery returned no result" })
                  break
                }
                prompts.log.info(source.id + ": processed_pages=" + result.pages +
                  " page_window=" + pageWindow + " candidates=" + result.candidates +
                  " queued_new=" + result.added + " blocked_auth=" + result.blocked_auth +
                  " errors=" + result.error_count)
                for (const error of result.errors) prompts.log.warn(error)

                const stats = ResearchQueue.stats(source.id)
                const blocked =
                  result.error_count > 0 ||
                  result.blocked_auth > 0 ||
                  stats.crawl_page_errors > 0 ||
                  stats.crawl_page_auth_blocked > 0 ||
                  stats.blocked_auth > 0
                if (blocked) {
                  const reason = [
                    result.error_count ? "discovery errors=" + result.error_count : "",
                    result.blocked_auth || stats.blocked_auth || stats.crawl_page_auth_blocked ? "authentication required" : "",
                    stats.crawl_page_errors ? "crawl-page errors=" + stats.crawl_page_errors : "",
                  ].filter(Boolean).join(", ") || "unresolved crawl state"
                  incomplete.push({ source: source.id, reason })
                  finished = true
                  continue
                }
                if (result.pages >= pageWindow) {
                  const nextWindow = pageWindow * 2
                  if (!Number.isSafeInteger(nextWindow) || nextWindow <= pageWindow) {
                    incomplete.push({ source: source.id, reason: "runtime integer range exhausted before pagination was proven complete" })
                    finished = true
                  } else {
                    pageWindow = nextWindow
                  }
                  continue
                }
                finished = true
              }
            }

            if (incomplete.length) {
              prompts.log.warn("Discovery is PARTIAL; unresolved sources:")
              for (const item of incomplete) prompts.log.warn(item.source + ": " + item.reason)
            } else {
              prompts.log.success("All selected sources exhausted their accessible discovery frontier.")
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
            .option("source", { type: "string", describe: "only process queue items from this source ID" })
            .option("watch", {
              type: "boolean",
              default: false,
              describe: "keep processing new queue items until interrupted",
            })
            .option("interval", { type: "number", default: 10, describe: "seconds between queue checks when idle" }),
        async handler(args) {
          prompts.intro("CyberStrike Research Learning Worker")
          do {
            const result = await learnResearchQueue({ limit: args.limit, workerID: args.worker, sourceID: args.source })
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
                result.failed +
                " blocked_auth=" +
                result.blocked_auth +
                " legacy_requeued=" + result.requeued_legacy,
            )
            for (const error of result.errors) prompts.log.warn(error)
            if (!args.watch) break
            if (result.claimed === 0 || result.failed > 0) await Bun.sleep(Math.max(2, args.interval) * 1000)
          } while (true)
        },
      })
      .command({
        command: "retry-auth",
        describe: "requeue authentication-blocked reports after configuring a valid source session",
        builder: (yargs) => yargs
          .option("source", { type: "string", describe: "optional source ID to retry" })
          .option("limit", { type: "number", default: 100, describe: "maximum blocked reports to requeue" }),
        async handler(args) {
          const count = await retryAuthenticatedResearch({
            sourceID: args.source,
            limit: args.limit,
            retryImmediately: true,
          })
          console.log("requeued_for_auth_retry=" + count)
          console.log("Only sources with a configured session are retried. Configure CYBERSTRIKE_RESEARCH_COOKIE_<SOURCE_ID> or CYBERSTRIKE_RESEARCH_AUTHORIZATION_<SOURCE_ID>; index pages resume through research discover/sync and reports through research learn.")
        },
      })
      .command({
        command: "queue-stats [source]",
        describe: "show persistent research queue counts by status",
        builder: (yargs) => yargs.positional("source", { type: "string", describe: "optional source ID filter" }),
        async handler(args) {
          const stats = ResearchQueue.stats(args.source)
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
        command: "enrich",
        describe: "re-extract legacy public research from locally stored excerpts without network fetches",
        builder: (yargs) => yargs
          .option("limit", { type: "number", default: 100, describe: "maximum legacy records to enrich per run" })
          .option("all", { type: "boolean", default: false, describe: "continue through all eligible legacy records" }),
        async handler(args) {
          prompts.intro("CyberStrike Local Research Enrichment")
          const rawLimit = typeof args.limit === "number" && Number.isFinite(args.limit) ? Math.floor(args.limit) : 100
          const requestedLimit = Math.max(1, Math.min(500, rawLimit))
          const totals = { scanned: 0, enriched: 0, skipped: 0, errors: 0 }
          do {
            const records = ReportKnowledge.externalRecordsForEnrichment(args.all ? 500 : requestedLimit, RESEARCH_LEARNING_VERSION)
            if (!records.length) break
            let enrichedThisBatch = 0
            for (const row of records) {
              totals.scanned++
              const metadata = row.metadata ?? {}
              const excerpt = typeof metadata.excerpt === "string" ? metadata.excerpt : ""
              const existingExtracted = metadata.extracted && typeof metadata.extracted === "object"
                ? metadata.extracted as Record<string, unknown>
                : {}
              try {
                const topic = classifyResearchTopic(row.title, excerpt)
                const vulnerabilityClass = topic ?? row.vulnerabilityClass ?? undefined
                const extracted = extractResearchDetails(row.title, excerpt, vulnerabilityClass)
                const cweID = extracted.cweID ?? row.cweID ?? undefined
                const oldSignals = Array.isArray(existingExtracted.retrieval_signals)
                  ? existingExtracted.retrieval_signals.filter((value): value is string => typeof value === "string")
                  : []
                const retrievalSignals = Array.from(new Set([
                  ...oldSignals,
                  ...extracted.retrievalSignals,
                  ...(vulnerabilityClass ? [vulnerabilityClass] : []),
                  ...(cweID ? [cweID] : []),
                ]))
                const nextExtracted: Record<string, unknown> = {
                  ...existingExtracted,
                  ...(vulnerabilityClass ? { vulnerability_class: vulnerabilityClass } : {}),
                  classification_method: "title-first-dominant-body-v2",
                  ...(extracted.severity !== "unknown" ? { severity: extracted.severity } : {}),
                  ...(cweID ? { cwe_id: cweID } : {}),
                  lesson: extracted.lesson ?? existingExtracted.lesson ?? row.lesson ?? null,
                  ...(extracted.attackVector ? { attack_vector: extracted.attackVector } : {}),
                  ...(extracted.impact ? { impact: extracted.impact } : {}),
                  ...(extracted.reproduction ? { reproduction_steps: extracted.reproduction } : {}),
                  ...(extracted.poc ? { poc_snippet: extracted.poc } : {}),
                  ...(extracted.prerequisites ? { prerequisites: extracted.prerequisites } : {}),
                  ...(extracted.verificationSignals ? { verification_signals: extracted.verificationSignals } : {}),
                  ...(extracted.falsePositiveCautions ? { false_positive_cautions: extracted.falsePositiveCautions } : {}),
                  ...(extracted.rootCause ? { root_cause: extracted.rootCause } : {}),
                  ...(extracted.requestResponseEvidence ? { request_response_evidence: extracted.requestResponseEvidence } : {}),
                  ...(extracted.affectedComponents ? { affected_components: extracted.affectedComponents } : {}),
                  ...(extracted.affectedVersions ? { affected_versions: extracted.affectedVersions } : {}),
                  ...(extracted.technologyStack ? { technology_stack: extracted.technologyStack } : {}),
                  ...(extracted.remediation ? { remediation: extracted.remediation } : {}),
                  ...(extracted.attackChain ? { attack_chain: extracted.attackChain } : {}),
                  ...(extracted.negativeEvidence ? { negative_evidence: extracted.negativeEvidence } : {}),
                  ...(extracted.limitations ? { limitations: extracted.limitations } : {}),
                  retrieval_signals: retrievalSignals,
                }
                const merged = [
                  nextExtracted.lesson ?? row.lesson,
                  nextExtracted.cwe_id ?? row.cweID,
                  nextExtracted.attack_vector ?? row.attackVector,
                  nextExtracted.impact ?? row.impact,
                  nextExtracted.reproduction_steps ?? row.reproduction,
                  nextExtracted.poc_snippet ?? row.poc,
                  nextExtracted.prerequisites,
                  nextExtracted.verification_signals,
                  nextExtracted.false_positive_cautions,
                  nextExtracted.root_cause,
                  nextExtracted.request_response_evidence,
                  nextExtracted.affected_components,
                  nextExtracted.affected_versions,
                  nextExtracted.technology_stack,
                  nextExtracted.remediation,
                  nextExtracted.attack_chain,
                  nextExtracted.negative_evidence,
                  nextExtracted.limitations,
                ]
                nextExtracted.extraction_coverage = {
                  present: merged.filter(Boolean).length,
                  total: 18,
                  note: "Field presence only; not a quality score or practical validation.",
                }
                const saved = ReportKnowledge.enrichExternalRecord({
                  id: row.id,
                  vulnerabilityClass,
                  cweID,
                  severity: extracted.severity,
                  lesson: extracted.lesson,
                  attackVector: extracted.attackVector,
                  impact: extracted.impact,
                  reproduction: extracted.reproduction,
                  poc: extracted.poc,
                  tags: retrievalSignals,
                  metadata: {
                    extraction_version: RESEARCH_LEARNING_VERSION,
                    study_method: "bounded-heuristic-extraction",
                    extracted: nextExtracted,
                  },
                })
                if (saved) {
                  totals.enriched++
                  enrichedThisBatch++
                } else {
                  totals.skipped++
                }
              } catch (error) {
                totals.errors++
                if (totals.errors <= 10) prompts.log.warn(row.id + " — " + (error instanceof Error ? error.message : String(error)))
              }
            }
            if (!args.all || enrichedThisBatch === 0) break
          } while (true)
          prompts.log.info(
            "scanned=" + totals.scanned +
            " enriched=" + totals.enriched +
            " skipped=" + totals.skipped +
            " errors=" + totals.errors,
          )
          prompts.outro("Legacy public research enrichment complete; no source URLs were fetched.")
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
          console.log("external_references_used=" + stats.externalReferencesUsed)
          console.log("external_reference_usefulness_events=" + stats.externalReferenceUsefulnessEvents)
        },
      })
      .demandCommand(),
  async handler() {},
})
