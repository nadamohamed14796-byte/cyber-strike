import { and, desc, eq, or, like, count, sql, isNull, notInArray } from "drizzle-orm"
import { Database } from "../storage/db"
import { Identifier } from "../id/id"
import { ReportKnowledgeEventTable, ReportKnowledgeTable } from "./report-knowledge.sql"
import { matchesSourceURLFingerprint, sourceFingerprints } from "./source-fingerprint"

export namespace ReportKnowledge {
  export type Outcome = "observed" | "useful" | "confirmed" | "rejected" | "duplicate" | "disproven"

  function normalize(value?: string | null) {
    return value?.trim().toLowerCase().replace(/\s+/g, " ") || ""
  }

  type FingerprintInput = {
    sessionID?: string
    title: string
    vulnerabilityClass?: string
    cweID?: string
    endpoint?: string
    sourceURL?: string
    targetPattern?: string
  }

  function legacyFingerprint(input: FingerprintInput) {
    return [input.vulnerabilityClass, input.cweID, input.endpoint, input.title].map(normalize).filter(Boolean).join("|")
  }

  function fingerprint(input: FingerprintInput) {
    // Reject blank titles at the persistence boundary. A session-scoped prefix
    // must not make an otherwise-empty fingerprint look valid.
    if (!input.title?.trim()) return ""
    if (input.sourceURL) return sourceFingerprints(input.sourceURL)[0]
    const legacy = legacyFingerprint(input)
    // Findings without a public source URL are local knowledge. Scope identity
    // to the session and/or explicit target pattern so equivalent paths on
    // separate targets cannot be merged into one record.
    // Session identifiers are case-sensitive keys; do not lowercase them.
    const sessionScope = input.sessionID?.trim() ?? ""
    const targetScope = normalize(input.targetPattern)
    return sessionScope || targetScope ? "scope:" + sessionScope + "|" + targetScope + "|" + legacy : legacy
  }

  function fingerprintCondition(input: FingerprintInput, key: string) {
    const keys = input.sourceURL
      ? sourceFingerprints(input.sourceURL)
      : Array.from(new Set([key, legacyFingerprint(input)]))
    return keys.length > 1
      ? or(...keys.map((value) => eq(ReportKnowledgeTable.fingerprint, value)))!
      : eq(ReportKnowledgeTable.fingerprint, keys[0])
  }

  function findFingerprintMatch(
    rows: (typeof ReportKnowledgeTable.$inferSelect)[],
    input: FingerprintInput,
    key: string,
  ) {
    const exact = rows.find((row) => row.fingerprint === key)
    if (exact && (!input.sourceURL || matchesSourceURLFingerprint(exact.source_url, key))) return exact

    if (input.sourceURL) {
      // Even when a legacy lowercase fingerprint happens to equal the incoming
      // URL text, only reuse it when the original stored URL canonicalizes to
      // the same case-preserving v2 identity.
      return rows.find((row) => matchesSourceURLFingerprint(row.source_url, key))
    }

    const legacy = legacyFingerprint(input)
    const targetScope = (value: string | null | undefined) => normalize(value) || undefined
    // Legacy local records are reusable only when their stored session and
    // target scope match exactly. Do not absorb rows that may have been merged
    // by the older unscoped fingerprint implementation.
    return rows.find(
      (row) =>
        row.fingerprint === legacy &&
        (row.session_id ?? undefined) === input.sessionID &&
        targetScope(row.target_pattern) === targetScope(input.targetPattern),
    )
  }

  function confidence(row: typeof ReportKnowledgeTable.$inferSelect, outcome?: Outcome) {
    const useful = row.times_useful + (outcome === "useful" || outcome === "confirmed" ? 1 : 0)
    const rejected =
      row.times_rejected + (outcome === "rejected" || outcome === "duplicate" || outcome === "disproven" ? 1 : 0)
    const total = useful + rejected
    return total ? Math.max(0, Math.min(100, Math.round((useful / total) * 100))) : row.confidence
  }

  export function ingest(input: {
    sessionID?: string
    vulnerabilityID?: string
    title: string
    vulnerabilityClass?: string
    cweID?: string
    severity: string
    endpoint?: string
    attackVector?: string
    impact?: string
    reproduction?: string
    poc?: string
    sourceKind?: string
    sourceURL?: string
    program?: string
    targetPattern?: string
    outcome?: Outcome
    lesson?: string
    tags?: string[]
    metadata?: Record<string, unknown>
    sourceTrust?: number
  }) {
    try {
      const now = Date.now()
      const key = fingerprint(input)
      if (!key) return null
      return Database.transaction((db) => {
        const matches = db.select().from(ReportKnowledgeTable).where(fingerprintCondition(input, key)).all()
        const existing = findFingerprintMatch(matches, input, key)
        if (existing) {
          db.update(ReportKnowledgeTable)
            .set({
              times_seen: existing.times_seen + 1,
              times_useful:
                existing.times_useful + (input.outcome === "useful" || input.outcome === "confirmed" ? 1 : 0),
              times_rejected:
                existing.times_rejected +
                (input.outcome === "rejected" || input.outcome === "duplicate" || input.outcome === "disproven"
                  ? 1
                  : 0),
              confidence: confidence(existing, input.outcome),
              status: input.outcome ?? existing.status,
              lesson: input.lesson ?? existing.lesson,
              metadata: input.metadata ?? existing.metadata,
              time_updated: now,
            })
            .where(eq(ReportKnowledgeTable.id, existing.id))
            .run()
          return existing.id
        }
        const id = Identifier.ascending("report_knowledge")
        const sourceTrust = Math.max(0, Math.min(100, Math.round(input.sourceTrust ?? 50)))
        const baseConfidence = Math.max(50, sourceTrust)
        db.insert(ReportKnowledgeTable)
          .values({
            id,
            session_id: input.sessionID ?? null,
            source_vulnerability_id: input.vulnerabilityID ?? null,
            fingerprint: key,
            title: input.title,
            vulnerability_class: input.vulnerabilityClass ?? null,
            cwe_id: input.cweID ?? null,
            severity: input.severity,
            status: input.outcome ?? "observed",
            source_kind: input.sourceKind ?? "finding",
            source_url: input.sourceURL ?? null,
            program: input.program ?? null,
            target_pattern: input.targetPattern ? normalize(input.targetPattern) : null,
            endpoint: input.endpoint ?? null,
            attack_vector: input.attackVector ?? null,
            impact: input.impact ?? null,
            reproduction: input.reproduction ?? null,
            poc: input.poc ?? null,
            outcome: input.outcome ?? null,
            lesson: input.lesson ?? null,
            tags: input.tags ?? [],
            metadata: input.metadata ?? {},
            confidence:
              input.outcome === "confirmed" || input.outcome === "useful"
                ? baseConfidence
                : Math.min(baseConfidence, 60),
            times_seen: 1,
            times_useful: input.outcome === "confirmed" || input.outcome === "useful" ? 1 : 0,
            times_rejected: 0,
            time_created: now,
            time_updated: now,
          })
          .run()
        return id
      })
    } catch (error) {
      console.warn("[cyberstrike] report knowledge persistence failed:", error)
      return null
    }
  }

  export type IngestExternalResult = { id: string; created: boolean }

  /** Return URLs already represented in the global external-report knowledge store. */
  export function externalSourceURLs(): string[] {
    return Database.use((db) =>
      db.select({ source_url: ReportKnowledgeTable.source_url })
        .from(ReportKnowledgeTable)
        .where(eq(ReportKnowledgeTable.source_kind, "external_report"))
        .all()
        .flatMap((row) => row.source_url ? [row.source_url] : []),
    )
  }

  export function ingestExternalDetailed(input: {
    title: string
    severity: string
    vulnerabilityClass?: string
    cweID?: string
    sourceURL: string
    program?: string
    targetPattern?: string
    endpoint?: string
    attackVector?: string
    impact?: string
    reproduction?: string
    poc?: string
    lesson?: string
    tags?: string[]
    metadata?: Record<string, unknown>
    sourceTrust?: number
  }): IngestExternalResult | null {
    try {
      const key = fingerprint(input)
      if (!key) return null

      // The lookup and update/insert must be one transaction. Separate reads
      // and writes let concurrent crawlers race through "not found" and one
      // duplicate then fails the unique fingerprint constraint instead of
      // resolving to the already-persisted record.
      return Database.transaction((db) => {
        const matches = db.select().from(ReportKnowledgeTable).where(fingerprintCondition(input, key)).all()
        const existing = findFingerprintMatch(matches, input, key)

        if (existing) {
          const now = Date.now()
          db.update(ReportKnowledgeTable)
            .set({
              times_seen: existing.times_seen + 1,
              lesson: input.lesson ?? existing.lesson,
              impact: input.impact ?? existing.impact,
              attack_vector: input.attackVector ?? existing.attack_vector,
              endpoint: input.endpoint ?? existing.endpoint,
              reproduction: input.reproduction ?? existing.reproduction,
              poc: input.poc ?? existing.poc,
              tags: input.tags?.length ? Array.from(new Set([...(existing.tags ?? []), ...input.tags])) : existing.tags,
              metadata: { ...(existing.metadata ?? {}), ...(input.metadata ?? {}) },
              time_updated: now,
            })
            .where(eq(ReportKnowledgeTable.id, existing.id))
            .run()
          return { id: existing.id, created: false }
        }

        const id = ingest({
          ...input,
          sourceKind: "external_report",
          outcome: "observed",
          sourceTrust: input.sourceTrust,
        })
        return id ? { id, created: true } : null
      })
    } catch (error) {
      console.warn("[cyberstrike] external report knowledge persistence failed:", error)
      return null
    }
  }

  export function ingestExternal(input: {
    title: string
    severity: string
    vulnerabilityClass?: string
    cweID?: string
    sourceURL: string
    program?: string
    targetPattern?: string
    endpoint?: string
    attackVector?: string
    impact?: string
    reproduction?: string
    poc?: string
    lesson?: string
    tags?: string[]
    metadata?: Record<string, unknown>
    sourceTrust?: number
  }) {
    return ingestExternalDetailed(input)?.id ?? null
  }

  export function recordOutcome(input: {
    reportID: string
    sessionID?: string
    outcome: Outcome
    signal?: string
    evidence?: string
    hook?: string
    metadata?: Record<string, unknown>
  }) {
    try {
      Database.transaction((db) => {
        const row = db.select().from(ReportKnowledgeTable).where(eq(ReportKnowledgeTable.id, input.reportID)).get()
        if (!row) return
        const now = Date.now()
        // Global external research is shared across every target. A validation
        // outcome from one session describes that target's test, not whether the
        // public source report itself is true or false for all other targets.
        // Preserve shared external rows as advisory references and store this
        // session-specific result only in the event ledger.
        const sharedExternalResearch =
          row.source_kind === "external_report" && !row.session_id && !normalize(row.target_pattern)
        if (!sharedExternalResearch) {
          db.update(ReportKnowledgeTable)
            .set({
              status: input.outcome,
              outcome: input.outcome,
              times_useful: row.times_useful + (input.outcome === "useful" || input.outcome === "confirmed" ? 1 : 0),
              times_rejected:
                row.times_rejected +
                (input.outcome === "rejected" || input.outcome === "duplicate" || input.outcome === "disproven" ? 1 : 0),
              confidence: confidence(row, input.outcome),
              time_updated: now,
            })
            .where(eq(ReportKnowledgeTable.id, input.reportID))
            .run()
        }
        db.insert(ReportKnowledgeEventTable)
          .values({
            id: Identifier.ascending("report_knowledge_event"),
            report_id: input.reportID,
            session_id: input.sessionID ?? row.session_id,
            hook: input.hook ?? "learning",
            outcome: input.outcome,
            signal: input.signal ?? null,
            evidence: input.evidence ?? null,
            metadata: input.metadata ?? {},
            time_created: now,
            time_updated: now,
          })
          .run()
      })
    } catch (error) {
      console.warn("[cyberstrike] report knowledge outcome persistence failed:", error)
    }
  }

  /**
   * Record feedback for a shared public reference without turning one target's
   * verdict into a global claim about whether the source report is true.
   *
   * Only an explicitly supplied "useful" outcome increases the cross-target
   * usefulness counter. Non-confirmed verdicts are telemetry only and never
   * penalize or disprove a public report.
   */
  export function recordReferenceUse(input: {
    reportID: string
    sessionID: string
    outcome: "observed" | "useful"
    signal?: string
    metadata?: Record<string, unknown>
  }): boolean {
    try {
      return Database.transaction((db) => {
        const row = db.select().from(ReportKnowledgeTable)
          .where(eq(ReportKnowledgeTable.id, input.reportID)).get()
        const trust = row?.metadata?.source_trust
        if (
          !row ||
          row.source_kind !== "external_report" ||
          row.session_id ||
          normalize(row.target_pattern) ||
          ["rejected", "disproven", "duplicate"].includes(row.status) ||
          typeof trust !== "number" ||
          !Number.isFinite(trust) ||
          trust < 0 ||
          trust > 100 ||
          !input.sessionID.trim()
        ) return false

        // Count a reference at most once per session and feedback outcome. This
        // keeps repeated validation retries from artificially inflating ranking.
        const existingEvent = db.select({ id: ReportKnowledgeEventTable.id })
          .from(ReportKnowledgeEventTable)
          .where(and(
            eq(ReportKnowledgeEventTable.report_id, input.reportID),
            eq(ReportKnowledgeEventTable.session_id, input.sessionID),
            eq(ReportKnowledgeEventTable.hook, "finding-validation"),
            eq(ReportKnowledgeEventTable.outcome, input.outcome),
          ))
          .get()
        if (existingEvent) return false

        const now = Date.now()
        db.insert(ReportKnowledgeEventTable).values({
          id: Identifier.ascending("report_knowledge_event"),
          report_id: input.reportID,
          session_id: input.sessionID,
          hook: "finding-validation",
          outcome: input.outcome,
          signal: input.signal ?? null,
          evidence: null,
          metadata: input.metadata ?? {},
          time_created: now,
          time_updated: now,
        }).run()

        if (input.outcome === "useful") {
          db.update(ReportKnowledgeTable)
            .set({ times_useful: row.times_useful + 1, time_updated: now })
            .where(eq(ReportKnowledgeTable.id, input.reportID))
            .run()
        }
        return true
      })
    } catch (error) {
      console.warn("[cyberstrike] research reference feedback persistence failed:", error)
      return false
    }
  }

  function boundedLimit(value: number | undefined, fallback: number, minimum: number, maximum: number) {
    const candidate = value === undefined || !Number.isFinite(value) ? fallback : value
    return Math.max(minimum, Math.min(Math.floor(candidate), maximum))
  }

  const QUERY_STOP_WORDS = new Set([
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "into", "is", "it",
    "of", "on", "or", "that", "the", "then", "this", "to", "using", "was", "were", "with",
    "reveals", "revealed", "shows", "showed", "found", "find", "when", "where", "while",
  ])

  const SIGNAL_PATTERNS: Array<[string, RegExp]> = [
    ["idor", /\bidor\b|insecure direct object|object[- ](?:level )?authorization|object[- ]identifier|resource identifier|object identifier|another user's? (?:data|object|account)/i],
    ["authorization-boundary", /authorization|access control|privilege escalation|role[- ]based access|another account/i],
    ["authentication-flow", /authentication|login|session fixation|password reset|account recovery/i],
    ["token-or-jwt", /\bjwt\b|bearer token|refresh token|access token|oauth/i],
    ["javascript-client", /javascript|\.m?js\b|source maps?|client[- ]side bundle|frontend script/i],
    ["api-endpoint", /\bapi\b|api route|endpoint|graphql|rest(?:ful)? route/i],
    ["file-upload", /file upload|multipart|content[- ]type|filename/i],
    ["cache-behavior", /cache[- ]control|cache poisoning|cache deception|cdn/i],
    ["cors-policy", /\bcors\b|cross-origin resource sharing|access[- ]control[- ]allow[- ]origin/i],
    ["information-disclosure", /information[- ]disclosure|sensitive information exposure|sensitive data exposure|data leakage|exposed sensitive data/i],
    ["privilege-escalation", /privilege[- ]escalation|vertical privilege[- ]escalation|horizontal privilege[- ]escalation/i],
    ["security-misconfiguration", /security[- ]misconfiguration|misconfiguration|insecure configuration/i],
    ["account-takeover", /account[- ]takeover|account compromise|\bato\b/i],
    ["race-condition", /race condition|concurrent|time[- ]of[- ]check|toctou/i],
    ["server-side-request", /\bssrf\b|server[- ]side request forgery|url fetch/i],
    ["injection-sink", /sql injection|command injection|template injection|deserialization/i],
    ["business-logic", /business logic|workflow|coupon|payment|quantity|state transition/i],
    ["graphql", /\bgraphql\b|graphql endpoint|graphql mutation/i],
    ["jwt", /\bjwt\b|json web token/i],
    ["oauth", /\boauth\b|open authorization/i],
    ["open-redirect", /open redirect|unvalidated redirect/i],
    ["path-traversal", /path traversal|directory traversal|parent directory/i],
    ["prototype-pollution", /prototype pollution|prototype chain pollution/i],
    ["deserialization", /insecure deserialization|unsafe deserialization|deserialize untrusted/i],
    ["request-smuggling", /request smuggling|http desynchronization|cl\.te|te\.cl/i],
    ["subdomain-takeover", /subdomain takeover|dangling cname/i],
    ["command-injection", /command injection|os command injection/i],
    ["web-cache", /web cache|cache deception/i],
  ]

  function canonicalSignals(query?: string) {
    if (!query) return []
    return SIGNAL_PATTERNS.filter(([, pattern]) => pattern.test(query)).map(([signal]) => signal)
  }

  function queryTokens(query?: string) {
    return Array.from(
      new Set(
        normalize(query)
          .split(/[^\p{L}\p{N}_-]+/u)
          .map((token) => token.trim())
          .filter((token) => token.length >= 2 && !QUERY_STOP_WORDS.has(token)),
      ),
    )
  }

  // A query that names a concrete vulnerability class must not be satisfied by
  // generic words such as "authorization", "API", or "security" in unrelated articles.
  const SPECIFIC_QUERY_PATTERNS: Array<[string, RegExp]> = [
    ["idor", /\bidor\b|insecure direct object|broken object level authorization|\bbola\b/i],
    ["xss", /cross[- ]site scripting|\bxss\b/i],
    ["ssrf", /\bssrf\b|server[- ]side request forgery/i],
    ["csrf", /\bcsrf\b|cross[- ]site request forgery/i],
    ["sqli", /\bsqli\b|sql injection/i],
    ["xxe", /\bxxe\b|xml external entity/i],
    ["ssti", /\bssti\b|server[- ]side template injection/i],
    ["race-condition", /race condition|time[- ]of[- ]check|\btoctou\b/i],
    ["open-redirect", /open redirect|unvalidated redirect/i],
    ["auth-bypass", /authentication bypass|auth bypass/i],
    ["access-control", /access control|authorization bypass|authorisation bypass|broken access control/i],
    ["cors", /\bcors\b|cross-origin resource sharing|access[- ]control[- ]allow[- ]origin/i],
    ["information-disclosure", /information[- ]disclosure|sensitive information exposure|sensitive data exposure|data leakage|exposed sensitive data/i],
    ["privilege-escalation", /privilege[- ]escalation|vertical privilege[- ]escalation|horizontal privilege[- ]escalation/i],
    ["security-misconfiguration", /security[- ]misconfiguration|misconfiguration|insecure configuration/i],
    ["account-takeover", /account[- ]takeover|account compromise|\bato\b/i],
    ["business-logic", /business logic/i],
    ["prototype-pollution", /prototype pollution/i],
    ["deserialization", /deserialization/i],
    ["request-smuggling", /request smuggling|http desynchronization/i],
    ["cache-poisoning", /cache poisoning/i],
    ["file-upload", /file upload/i],
    ["graphql", /\bgraphql\b/i],
    ["jwt", /\bjwt\b|json web token/i],
    ["command-injection", /command injection|os command injection/i],
    ["path-traversal", /path traversal|directory traversal/i],
    ["subdomain-takeover", /subdomain takeover|dangling cname/i],
    ["oauth", /\boauth\b|open authorization/i],
    ["web-cache", /web cache|cache deception/i],
  ]

  function specificQuerySignals(query?: string) {
    if (!query) return []
    return SPECIFIC_QUERY_PATTERNS.filter(([, pattern]) => pattern.test(query)).map(([signal]) => signal)
  }

  function matchesSpecificQuery(row: typeof ReportKnowledgeTable.$inferSelect, requested: string[]) {
    if (!requested.length) return true
    const metadata = row.metadata ?? {}
    const extracted = metadata.extracted && typeof metadata.extracted === "object"
      ? metadata.extracted as Record<string, unknown>
      : {}
    const storedSignals = new Set([
      ...((Array.isArray(extracted.retrieval_signals) ? extracted.retrieval_signals : []) as unknown[])
        .filter((value): value is string => typeof value === "string").map(normalize),
      ...(row.tags ?? []).map(normalize),
      normalize(row.vulnerability_class),
    ])
    const corpus = [
      row.title, row.vulnerability_class, row.cwe_id, row.lesson, row.attack_vector,
      row.impact, row.reproduction, row.poc, JSON.stringify(metadata),
    ].filter(Boolean).join(" ")
    const concreteClasses = requested.filter((signal) => signal !== "access-control" && signal !== "auth-bypass")
    // If the query names a concrete class (IDOR, SSRF, XSS, etc.), require the
    // record's primary class or title to agree. A passing mention buried in a
    // long excerpt is not enough to make an unrelated article a match.
    if (concreteClasses.length) {
      const classificationMethod = typeof extracted.classification_method === "string"
        ? extracted.classification_method
        : undefined
      return concreteClasses.some((signal) => {
        const pattern = SPECIFIC_QUERY_PATTERNS.find(([name]) => name === signal)?.[1]
        const titleMatches = Boolean(pattern?.test(row.title))
        const currentClassificationMatches =
          ["title-first-dominant-body-v1", "title-first-dominant-body-v2"].includes(classificationMethod ?? "") &&
        normalize(row.vulnerability_class) === signal
        return titleMatches || currentClassificationMatches
      })
    }
    return requested.some((signal) => {
      if (storedSignals.has(signal)) return true
      const pattern = SPECIFIC_QUERY_PATTERNS.find(([name]) => name === signal)?.[1]
      return Boolean(pattern?.test(corpus))
    })
  }

  function relevanceScore(row: typeof ReportKnowledgeTable.$inferSelect, tokens: string[], signals: string[] = []) {
    if (!tokens.length && !signals.length) return 0
    const title = normalize(row.title)
    const lesson = normalize(row.lesson)
    const attackVector = normalize(row.attack_vector)
    const impact = normalize(row.impact)
    const reproduction = normalize(row.reproduction)
    const poc = normalize(row.poc)
    const tags = normalize((row.tags ?? []).join(" "))
    const metadataValue = row.metadata ?? {}
    const extracted = metadataValue.extracted && typeof metadataValue.extracted === "object"
      ? metadataValue.extracted as Record<string, unknown>
      : {}
    const storedSignals = new Set([
      ...((Array.isArray(extracted.retrieval_signals) ? extracted.retrieval_signals : []) as unknown[]).filter((v): v is string => typeof v === "string").map(normalize),
      ...(row.tags ?? []).map(normalize),
    ])
    const metadata = normalize(JSON.stringify(metadataValue))
    const haystack = [title, lesson, attackVector, impact, reproduction, poc, tags, metadata].filter(Boolean).join(" ")
    let score = 0
    for (const signal of signals) {
      if (storedSignals.has(signal)) score += 55
      else if (tags.includes(signal) || metadata.includes(signal)) score += 28
    }

    for (const token of tokens) {
      const escaped = token.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")
      const exact = new RegExp("(^|[^\\p{L}\\p{N}_])" + escaped + "([^\\p{L}\\p{N}_]|$)", "iu")
      if (exact.test(title)) score += 45
      else if (exact.test(lesson)) score += 25
      else if (exact.test(attackVector) || exact.test(impact)) score += 18
      else if (exact.test(reproduction) || exact.test(poc)) score += 22
      else if (exact.test(tags)) score += 24
      else if (exact.test(metadata)) score += 18
      else if (haystack.includes(token)) score += 8
    }

    if (row.vulnerability_class && tokens.includes(normalize(row.vulnerability_class))) score += 70
    if (row.cwe_id && tokens.includes(normalize(row.cwe_id))) score += 70
    if (row.source_kind === "external_report") score += 5
    score += Math.min(row.times_useful * 4, 20)
    return score
  }

  export function search(
    input: {
      query?: string
      vulnerabilityClass?: string
      cweID?: string
      targetPattern?: string
      sourceKind?: string
      /** Filter target-scoped and terminally rejected rows before ranking/slicing. */
      publicReferencesOnly?: boolean
      limit?: number
    } = {},
  ) {
    const limit = boundedLimit(input.limit, 20, 0, 100)
    if (limit === 0) return []
    try {
      const requestedLimit = input.limit ?? 20
      const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(Math.trunc(requestedLimit), 100)) : 20
      return Database.use((db) => {
        const conditions = []
        if (input.vulnerabilityClass)
          conditions.push(eq(ReportKnowledgeTable.vulnerability_class, normalize(input.vulnerabilityClass)))
        if (input.cweID) conditions.push(eq(ReportKnowledgeTable.cwe_id, input.cweID))
        if (input.targetPattern)
          conditions.push(eq(ReportKnowledgeTable.target_pattern, normalize(input.targetPattern)))
        if (input.sourceKind) conditions.push(eq(ReportKnowledgeTable.source_kind, input.sourceKind))
        if (input.publicReferencesOnly) {
          conditions.push(isNull(ReportKnowledgeTable.session_id))
          conditions.push(or(isNull(ReportKnowledgeTable.target_pattern), eq(ReportKnowledgeTable.target_pattern, ""))!)
          conditions.push(notInArray(ReportKnowledgeTable.status, ["rejected", "disproven", "duplicate"]))
        }

        const tokens = queryTokens(input.query)
        const signals = canonicalSignals(input.query)
        const specificSignals = specificQuerySignals(input.query)
        if (tokens.length || signals.length) {
          const candidateConditions = [
            ...tokens.flatMap((token) => {
              const q = "%" + token + "%"
              return [
                like(ReportKnowledgeTable.title, q),
                like(ReportKnowledgeTable.lesson, q),
                like(ReportKnowledgeTable.attack_vector, q),
                like(ReportKnowledgeTable.impact, q),
                like(ReportKnowledgeTable.reproduction, q),
                like(ReportKnowledgeTable.poc, q),
                like(ReportKnowledgeTable.tags, q),
                like(sql<string>`${ReportKnowledgeTable.metadata}`, q),
                like(ReportKnowledgeTable.vulnerability_class, q),
                like(ReportKnowledgeTable.cwe_id, q),
              ]
            }),
            ...signals.flatMap((signal) => [
              like(ReportKnowledgeTable.tags, "%" + signal + "%"),
              like(sql<string>`${ReportKnowledgeTable.metadata}`, "%" + signal + "%"),
            ]),
          ]
          if (candidateConditions.length) conditions.push(or(...candidateConditions)!)
        }

        const query = db.select().from(ReportKnowledgeTable)
        const rows = (conditions.length ? query.where(and(...conditions)) : query)
          .orderBy(desc(ReportKnowledgeTable.time_updated))
          .limit(tokens.length || signals.length ? 500 : limit)
          .all()

        return rows
          // Enforce explicit vulnerability intent before scoring. Broad secondary
          // signals like authorization-boundary must not pull unrelated XSS/SSRF posts
          // into an IDOR-specific result set.
          .filter((row) => matchesSpecificQuery(row, specificSignals))
          .map((row) => ({ row, score: relevanceScore(row, tokens, signals) }))
          .filter(({ score }) => (!(tokens.length || signals.length) || score >= 20))
          .sort(
            (a, b) =>
              b.score - a.score ||
              b.row.confidence - a.row.confidence ||
              b.row.times_useful - a.row.times_useful ||
              b.row.time_updated - a.row.time_updated,
          )
          .slice(0, limit)
          .map(({ row }) => row)
      })
    } catch {
      return []
    }
  }
  export function stats() {
    try {
      return Database.use((db) => {
        const total = Number(db.select({ count: count() }).from(ReportKnowledgeTable).get()?.count ?? 0)
        const external = Number(
          db
            .select({ count: count() })
            .from(ReportKnowledgeTable)
            .where(eq(ReportKnowledgeTable.source_kind, "external_report"))
            .get()?.count ?? 0,
        )
        const useful = Number(
          db
            .select({ count: count() })
            .from(ReportKnowledgeTable)
            .where(or(eq(ReportKnowledgeTable.status, "useful"), eq(ReportKnowledgeTable.status, "confirmed")))
            .get()?.count ?? 0,
        )
        const rejected = Number(
          db
            .select({ count: count() })
            .from(ReportKnowledgeTable)
            .where(
              or(
                eq(ReportKnowledgeTable.status, "rejected"),
                eq(ReportKnowledgeTable.status, "disproven"),
                eq(ReportKnowledgeTable.status, "duplicate"),
              ),
            )
            .get()?.count ?? 0,
        )
        return { total, external, useful, rejected }
      })
    } catch {
      return { total: 0, external: 0, useful: 0, rejected: 0 }
    }
  }

  export function recommendations(
    input: {
      signal?: string
      vulnerabilityClass?: string
      cweID?: string
      targetPattern?: string
      sourceKind?: string
      limit?: number
    } = {},
  ) {
    // Runtime recommendations are reusable public references only. Local findings and
    // triage lessons can contain target-specific details, so they remain available to
    // explicit search but are never mixed into cross-target hunting context.
    const limit = boundedLimit(input.limit, 8, 1, 50)
    const rows = search({
      query: input.signal,
      vulnerabilityClass: input.vulnerabilityClass,
      cweID: input.cweID,
      sourceKind: "external_report",
      publicReferencesOnly: true,
      limit: Math.min(limit * 3, 100),
    })
    return (
      rows
        // Public imports are advisory, not validated findings. Use the source's
        // explicit trust metadata for those records; use outcome confidence for
        // locally triaged/validated knowledge and never recommend terminal rejects.
        .filter((row) => {
          // A public-source kind alone is not sufficient: some external records
          // may be attached to one session or an explicit target pattern. Keep
          // those out of shared hunting context to prevent cross-target leakage.
          if (row.session_id || normalize(row.target_pattern)) return false
          if (["rejected", "disproven", "duplicate"].includes(row.status)) return false
          if (row.source_kind === "external_report" && row.status === "observed") {
            const trust = row.metadata?.source_trust
            // Keep externally imported material advisory regardless of trust;
            // require a valid score to disclose provenance, but never promote it
            // into a validated finding based on source reputation alone.
            return typeof trust === "number" && Number.isFinite(trust) && trust >= 0 && trust <= 100
          }
          return row.confidence >= 50
        })
        // search() already ranks by query relevance, then confidence/usefulness.
        // Do not replace that ordering with a confidence-only sort.
        .slice(0, limit)
    )
  }
}
