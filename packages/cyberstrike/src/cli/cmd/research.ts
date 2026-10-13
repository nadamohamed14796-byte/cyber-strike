import * as prompts from "@clack/prompts"
import { cmd } from "./cmd"
import { ReportKnowledge } from "../../learning/report-knowledge"
import { RESEARCH_SOURCES } from "../../research/sources"
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
          // Resume blocked reports and crawl pages only when this source has an operator-provided session.
          const authRequeued = await retryAuthenticatedResearch({
            sourceID: args.source,
            limit: exhaustive ? 500 : args.limit,
          })
          if (authRequeued > 0) prompts.log.info("auth-blocked reports resumed=" + authRequeued)
          const discoveries = await discoverResearch({
            sourceID: args.source,
            pages: exhaustive ? 1000 : deep ? 750 : args.pages,
            depth: exhaustive ? 4 : deep ? 3 : args.depth,
          })
          for (const result of discoveries) {
            prompts.log.info(result.source + ": pages=" + result.pages + " candidates=" + result.candidates +
              " queued_new=" + result.added + " blocked_auth=" + result.blocked_auth)
            for (const error of result.errors) prompts.log.warn(error)
          }
          const limit = exhaustive ? 500 : Math.min(500, (deep ? 200 : args.limit) * discoveries.length)
          const learned = { claimed: 0, learned: 0, skipped: 0, failed: 0, blocked_auth: 0, errors: [] as string[] }
          // --all means drain the currently claimable queue, not just its first
          // 500 items. A failed item is retried on the next batch and eventually
          // reaches a terminal state; ordinary sync remains bounded to one batch.
          do {
            const batch = await learnResearchQueue({ limit, sourceID: args.source })
            learned.claimed += batch.claimed
            learned.learned += batch.learned
            learned.skipped += batch.skipped
            learned.failed += batch.failed
            learned.blocked_auth += batch.blocked_auth
            learned.errors.push(...batch.errors.slice(0, Math.max(0, 20 - learned.errors.length)))
            if (!exhaustive || batch.claimed === 0) break
          } while (true)
          prompts.log.info("queue worker: claimed=" + learned.claimed + " learned=" + learned.learned +
            " skipped=" + learned.skipped + " failed=" + learned.failed + " blocked_auth=" + learned.blocked_auth)
          for (const error of learned.errors) prompts.log.warn(error)
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
            const authRequeued = await retryAuthenticatedResearch({ sourceID: args.source, limit: args.pages })
            if (authRequeued > 0) prompts.log.info("auth-blocked research resumed=" + authRequeued)
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
                result.blocked_auth,
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
          const requestedLimit = Number.isFinite(args.limit) ? Math.max(1, Math.min(500, Math.floor(args.limit))) : 100
          const totals = { scanned: 0, enriched: 0, skipped: 0, errors: 0 }
          do {
            const records = ReportKnowledge.externalRecordsForEnrichment(args.all ? 500 : requestedLimit)
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
                    extraction_version: 7,
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
