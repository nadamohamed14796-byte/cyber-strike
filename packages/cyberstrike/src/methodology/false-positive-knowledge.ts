import { createHash } from "node:crypto"
import { and, desc, eq, isNull, or } from "../storage/db"
import { Database } from "../storage/db"
import { Identifier } from "../id/id"
import { FalsePositiveKnowledgeTable } from "./false-positive-knowledge.sql"

type FindingLike = {
  id: string
  title: string
  description: string
  endpoint?: string | null
}

const CLASS_PATTERNS: Array<[string, RegExp]> = [
  ["idor_bola", /\b(?:idor|bola|object[- ]level authorization|broken access control)\b/i],
  ["xss", /\b(?:xss|cross[- ]site scripting)\b/i],
  ["sqli", /\b(?:sql injection|sqli)\b/i],
  ["ssrf", /\b(?:ssrf|server[- ]side request forgery)\b/i],
  ["csrf", /\b(?:csrf|cross[- ]site request forgery)\b/i],
  ["authentication", /\b(?:authentication bypass|account takeover|mfa bypass|session fixation)\b/i],
  ["authorization", /\b(?:authorization|privilege escalation|access control|permission bypass)\b/i],
  ["cors", /\b(?:cors|cross[- ]origin)\b/i],
  ["open_redirect", /\b(?:open redirect|unvalidated redirect)\b/i],
  ["information_disclosure", /\b(?:information disclosure|sensitive data exposure|data leakage)\b/i],
  ["rate_limit", /\b(?:rate limit|rate limiting|brute force)\b/i],
  ["business_logic", /\b(?:business logic|workflow bypass|race condition)\b/i],
]

function classify(value: string) {
  return CLASS_PATTERNS.find(([, pattern]) => pattern.test(value))?.[0] ?? "other"
}

function normalizeTitle(value: string) {
  return value.toLowerCase()
    .replace(/https?:\/\/[^\s)]+/g, " ")
    .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "{uuid}")
    .replace(/\b\d{2,}\b/g, "{n}")
    .replace(/[^a-z0-9{} ]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 240) || "unspecified finding"
}

function normalizeEndpoint(value?: string | null) {
  if (!value) return null
  const candidate = value.trim().replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i, "")
  try {
    const url = new URL(candidate)
    return url.pathname
      .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "{uuid}")
      .replace(/\b\d{2,}\b/g, "{n}")
      .replace(/\/{2,}/g, "/")
      .slice(0, 300)
  } catch {
    return candidate.split("?")[0]
      .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "{uuid}")
      .replace(/\b\d{2,}\b/g, "{n}")
      .slice(0, 300)
  }
}

/** Store concise sanitized patterns, never raw HTTP requests, cookies, tokens, or PoCs. */
function safeText(value: string, max = 1200) {
  return value
    // Cookie headers contain multiple semicolon-delimited credentials; redact the whole
    // header line instead of only its first value.
    .replace(/\b(cookie|set-cookie)\s*[:=]\s*[^\r\n]*/gi, "$1=[REDACTED]")
    .replace(/\b(authorization|cookie|set-cookie|x-api-key|access_token|refresh_token|password|secret)\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+/gi, "$1=[REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, "[JWT REDACTED]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[EMAIL REDACTED]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[IP REDACTED]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max)
}

export namespace FalsePositiveKnowledge {
  export function record(input: {
    finding: FindingLike
    validationID: string
    failedCheckIDs: string[]
    checks: Array<{ id: string; status: string; reason: string | null; evidence: string | null }>
    summary: string
  }) {
    const combined = [input.finding.title, input.finding.description].join(" ")
    const vulnerabilityClass = classify(combined)
    const titlePattern = normalizeTitle(input.finding.title)
    const endpointPattern = normalizeEndpoint(input.finding.endpoint)
    const failedCheckIDs = [...new Set(input.failedCheckIDs)].sort()
    const benignCheck = input.checks.find((check) => check.id === "benign_behavior_ruled_out" && check.status === "fail")
    const benignExplanation = safeText(
      [benignCheck?.reason, benignCheck?.evidence].filter(Boolean).join(" — ") ||
      input.summary,
      1200,
    )
    const evidenceSummary = safeText(
      "Evidence-backed false-positive assessment. Contradictory checks: " +
      failedCheckIDs.join(", ") + ". " + input.summary,
      1200,
    )
    const fingerprint = createHash("sha256")
      .update([vulnerabilityClass, titlePattern, endpointPattern ?? "", failedCheckIDs.join(",")].join("|"))
      .digest("hex")
    const now = Date.now()

    Database.transaction((db) => {
      const existing = db.select().from(FalsePositiveKnowledgeTable)
        .where(eq(FalsePositiveKnowledgeTable.fingerprint, fingerprint)).get()
      if (existing) {
        db.update(FalsePositiveKnowledgeTable).set({
          occurrences: existing.occurrences + 1,
          confidence: Math.min(95, existing.confidence + (existing.source_finding_id === input.finding.id ? 0 : 5)),
          benign_explanation: benignExplanation,
          evidence_summary: evidenceSummary,
          source_validation_id: input.validationID,
          source_finding_id: input.finding.id,
          last_verdict: "false_positive",
          active: 1,
          time_updated: now,
        }).where(eq(FalsePositiveKnowledgeTable.id, existing.id)).run()
      } else {
        db.insert(FalsePositiveKnowledgeTable).values({
          id: Identifier.ascending("false_positive_knowledge"),
          fingerprint,
          vulnerability_class: vulnerabilityClass,
          title_pattern: titlePattern,
          endpoint_pattern: endpointPattern,
          failed_check_ids: failedCheckIDs,
          benign_explanation: benignExplanation,
          evidence_summary: evidenceSummary,
          source_validation_id: input.validationID,
          source_finding_id: input.finding.id,
          confidence: 50,
          occurrences: 1,
          last_verdict: "false_positive",
          active: 1,
          time_created: now,
          time_updated: now,
        }).run()
      }
    })
  }

  /** Deactivate a lesson when later evidence reopens its source finding. */
  export function reopenForFinding(findingID: string) {
    Database.use((db) => db.update(FalsePositiveKnowledgeTable).set({
      active: 0,
      last_verdict: "reopened",
      time_updated: Date.now(),
    }).where(eq(FalsePositiveKnowledgeTable.source_finding_id, findingID)).run())
  }

  /** Return advisory matches only. A historical false positive never auto-rejects a new finding. */
  export function similar(input: { title: string; description: string; endpoint?: string | null; offset?: number; pageSize?: number }) {
    const vulnerabilityClass = classify([input.title, input.description].join(" "))
    const titlePattern = normalizeTitle(input.title)
    const endpointPattern = normalizeEndpoint(input.endpoint)
    const rows = Database.use((db) => db.select().from(FalsePositiveKnowledgeTable)
      .where(and(eq(FalsePositiveKnowledgeTable.vulnerability_class, vulnerabilityClass), or(eq(FalsePositiveKnowledgeTable.active, 1), isNull(FalsePositiveKnowledgeTable.active))))
      .orderBy(desc(FalsePositiveKnowledgeTable.time_updated))
      .all())
    const words = new Set(titlePattern.split(" ").filter((word) => word.length >= 4 && !["with", "from", "that", "when", "this", "into"].includes(word)))
    const ranked = rows.map((row) => {
      const rowWords = new Set(row.title_pattern.split(" ").filter((word) => word.length >= 4))
      const overlap = [...words].filter((word) => rowWords.has(word)).length
      const titleScore = words.size ? overlap / words.size : 0
      const endpointScore = endpointPattern && row.endpoint_pattern === endpointPattern ? 0.35 : 0
      const classScore = vulnerabilityClass !== "other" && row.vulnerability_class === vulnerabilityClass ? 0.2 : 0
      return { row, score: Math.min(1, titleScore * 0.45 + endpointScore + classScore) }
    })
      .filter((item) => item.score >= 0.25)
      .sort((a, b) => b.score - a.score || b.row.time_updated - a.row.time_updated)
      .map(({ row, score }) => ({
        id: row.id,
        vulnerabilityClass: row.vulnerability_class,
        titlePattern: row.title_pattern,
        endpointPattern: row.endpoint_pattern,
        failedCheckIDs: row.failed_check_ids,
        benignExplanation: row.benign_explanation,
        evidenceSummary: row.evidence_summary,
        confidence: row.confidence,
        occurrences: row.occurrences,
        similarity: Math.round(score * 100),
      }))
    const offset = Math.max(0, Math.trunc(input.offset ?? 0))
    const pageSize = Math.max(1, Math.trunc(input.pageSize ?? 10))
    const matches = ranked.slice(offset, offset + pageSize)
    return {
      matches,
      total: ranked.length,
      offset,
      nextOffset: offset + matches.length < ranked.length ? offset + matches.length : null,
      hasMore: offset + matches.length < ranked.length,
    }
  }
}
