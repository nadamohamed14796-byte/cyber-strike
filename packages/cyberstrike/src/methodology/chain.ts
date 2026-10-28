import { Database, and, eq, inArray } from "../storage/db"
import { ChainCandidateTable } from "./methodology.sql"
import { ChainFindingLinkTable, type ChainFindingRelation } from "./chain-finding-link.sql"
import { VulnerabilityTable } from "../session/session.sql"
import { Identifier } from "../id/id"
import { Intel } from "./intel"

// ============================================================
// CHAIN DETECTION ENGINE — 8 vulnerability chain patterns
// Detects when multiple low-severity findings combine into
// high-impact exploitation chains
// ============================================================

export namespace Chain {
  export type Pattern =
    | "credential_endpoint"
    | "info_disclosure_ssrf"
    | "redirect_oauth"
    | "idor_data_leak"
    | "xss_csrf"
    | "ssti_rce"
    | "race_condition_business"
    | "information_amplification"
    | "custom"

  export interface Candidate {
    id: string
    pattern: Pattern
    entryIDs: string[]
    entryTitles: string[]
    assets: string[]
    expectedImpact: string
    severity: string
    testingPlan: string
    status: "detected" | "testing" | "confirmed" | "disproven"
    confidence: number
    detectedAt: number
    findingLinks?: FindingLink[]
  }

  const OAUTH_REGEX = /\b(oauth|authorize|callback|redirect_uri|token|sso|saml|openid)\b/i
  const STATE_CHANGE_REGEX = /\b(POST|PUT|DELETE|PATCH|create|update|delete|transfer|payment|invite|admin)\b/i
  const USER_DATA_REGEX = /\b(user|profile|account|email|phone|address|personal|private|settings)\b/i
  const PAYMENT_REGEX = /\b(payment|transfer|order|checkout|cart|purchase|balance|credit|withdraw|deposit)\b/i

  // --- Detection ---

  export function detect(sessionID: string): Candidate[] {
    const entries = Intel.get(sessionID)
    if (entries.length === 0) return []

    const checks = Intel.getVrtChecks(sessionID)
    const checkMap = new Map<string, Array<{ category: string; status: string }>>()
    for (const check of checks) {
      if (!checkMap.has(check.entryID)) checkMap.set(check.entryID, [])
      checkMap.get(check.entryID)!.push({ category: check.category, status: check.status })
    }

    const hasVulnCheck = (entry: Intel.Entry, cat: string) =>
      (checkMap.get(entry.id) ?? []).some(
        (c) => c.category.toLowerCase().includes(cat.toLowerCase()) && c.status === "tested_vulnerable",
      )

    const hostname = (asset: string) => {
      try {
        return new URL(asset.includes("://") ? asset : `https://${asset}`).hostname.toLowerCase().replace(/\.$/, "")
      } catch {
        return asset.toLowerCase().replace(/^https?:\/\//, "").split(/[/:?#]/, 1)[0].replace(/\.$/, "")
      }
    }
    // Avoid naive last-two-label matching (e.g. unrelated hosts under co.uk).
    const TWO_PART_SUFFIXES = new Set(["co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","edu.au","co.nz","org.nz","com.br","com.mx","com.ar","co.jp","co.kr","com.sg","com.tr","com.cn","com.hk","co.in","firm.in","net.in","org.in"])
    const registrableDomain = (asset: string) => {
      const labels = hostname(asset).split(".").filter(Boolean)
      if (labels.length < 2) return labels.join(".")
      const lastTwo = labels.slice(-2).join(".")
      return labels.slice(-(TWO_PART_SUFFIXES.has(lastTwo) ? 3 : 2)).join(".")
    }
    const sameAssetOrRelated = (a: Intel.Entry, b: Intel.Entry) => {
      const aa = hostname(a.asset)
      const ba = hostname(b.asset)
      return !!aa && !!ba && (aa === ba || registrableDomain(aa) === registrableDomain(ba))
    }

    const chains: Candidate[] = []
    const seen = new Set<string>()

    const addChain = (
      pattern: Pattern,
      a: Intel.Entry,
      b: Intel.Entry,
      impact: string,
      sev: string,
      plan: string,
      conf: number,
    ) => {
      const key = `${pattern}:${[a.id, b.id].sort().join("+")}`
      if (seen.has(key)) return
      seen.add(key)
      chains.push({
        id: Identifier.ascending("chain_candidate"),
        pattern,
        entryIDs: [...new Set([a.id, b.id])],
        entryTitles: [...new Set([a.title, b.title])],
        assets: [...new Set([a.asset, b.asset])],
        expectedImpact: impact,
        severity: sev,
        testingPlan: plan,
        status: "detected",
        confidence: conf,
        detectedAt: Date.now(),
      })
    }

    const credentials = entries.filter((e) => e.type === "credential")
    const endpoints = entries.filter((e) => e.type === "endpoint")
    const services = entries.filter((e) => e.type === "configuration" || e.type === "infrastructure")

    // Informational observations are useful as chain inputs even when each one is only INFO/LOW.
    // This creates a hypothesis for targeted validation; it never upgrades or approves a finding.
    const infoSignals = entries.filter((entry) => entry.severity === "info" || entry.severity === "low")
    const signalText = (entry: Intel.Entry) =>
      `${entry.type} ${entry.title} ${entry.detail ?? ""} ${entry.tags.join(" ")}`.toLowerCase()
    const hasInternalContext = (entry: Intel.Entry) =>
      entry.type === "configuration" ||
      entry.type === "infrastructure" ||
      /internal|private[- ]?(?:host|network|api|service)|localhost|127\.0\.0\.1|10\.\\d+\.\\d+\.\\d+|192\.168\.|172\.(?:1[6-9]|2\\d|3[01])\.|staging|admin[- ]?host|environment variable|deployment config/.test(signalText(entry))
    const hasRouteSurface = (entry: Intel.Entry) =>
      entry.type === "endpoint" ||
      entry.type === "api_schema" ||
      /openapi|swagger|graphql|rest api|route list|source map|sourcemap|api path|endpoint|websocket|rpc method/.test(signalText(entry))
    const hasIdentityContext = (entry: Intel.Entry) =>
      entry.type === "authentication_flow" ||
      entry.type === "business_rule" ||
      /tenant|organization|workspace|role|permission|authorization|access control|account owner|ownership|user id|object id|session boundary/.test(signalText(entry))
    const hasSensitiveDataContext = (entry: Intel.Entry) =>
      entry.type === "sensitive_data" ||
      /personal data|sensitive data|customer record|email address|phone number|invoice|payment details|account data|user profile|private record/.test(signalText(entry))
    const hasDebugContext = (entry: Intel.Entry) =>
      /stack trace|stacktrace|backtrace|debug output|debug mode|verbose error|exception trace|source path|absolute path|framework version|runtime version/.test(signalText(entry))

    const infoChainRules: Array<{
      matches: (a: Intel.Entry, b: Intel.Entry) => boolean
      impact: string
      severity: string
      plan: (a: Intel.Entry, b: Intel.Entry) => string
      confidence: number
    }> = [
      {
        matches: (a, b) =>
          (hasInternalContext(a) && hasRouteSurface(b)) ||
          (hasInternalContext(b) && hasRouteSurface(a)),
        impact: "POTENTIAL_INTERNAL_API_OR_SERVICE_EXPOSURE",
        severity: "high",
        plan: (a, b) =>
          `Correlate informational observations "${a.title}" and "${b.title}" to determine whether a disclosed internal service/route is actually reachable and exposes a security boundary. Use only in-scope endpoints and an authorized test identity; do not treat names or paths alone as impact.`,
        confidence: 40,
      },
      {
        matches: (a, b) =>
          (hasIdentityContext(a) && hasSensitiveDataContext(b)) ||
          (hasIdentityContext(b) && hasSensitiveDataContext(a)),
        impact: "POTENTIAL_CROSS_TENANT_OR_PRIVATE_DATA_ACCESS",
        severity: "high",
        plan: (a, b) =>
          `Using the approved test accounts and non-sensitive test records, verify whether "${a.title}" plus "${b.title}" reveals a real ownership/authorization gap. Compare owner and non-owner access with a baseline and negative control; do not infer IDOR or cross-tenant access from metadata alone.`,
        confidence: 45,
      },
      {
        matches: (a, b) =>
          (hasDebugContext(a) && (hasInternalContext(b) || hasSensitiveDataContext(b))) ||
          (hasDebugContext(b) && (hasInternalContext(a) || hasSensitiveDataContext(a))),
        impact: "POTENTIAL_SENSITIVE_CONTEXT_OR_ARCHITECTURE_DISCLOSURE",
        severity: "medium",
        plan: (a, b) =>
          `Check whether "${a.title}" and "${b.title}" jointly reveal non-public paths, deployment details, or sensitive context beyond what is intentionally public. Redact data and validate reachability/impact without accessing unrelated records.`,
        confidence: 35,
      },
      {
        matches: (a, b) =>
          (hasRouteSurface(a) && hasSensitiveDataContext(b)) ||
          (hasRouteSurface(b) && hasSensitiveDataContext(a)),
        impact: "POTENTIAL_SENSITIVE_DATA_API_SURFACE",
        severity: "medium",
        plan: (a, b) =>
          `Map "${a.title}" to "${b.title}" and verify, using an approved test identity and synthetic/test data, whether the route actually returns information beyond the caller's permissions. A schema, route, or data label by itself is not a vulnerability.`,
        confidence: 35,
      },
    ]

    for (let i = 0; i < infoSignals.length; i++) {
      const a = infoSignals[i]!
      for (let j = i + 1; j < infoSignals.length; j++) {
        const b = infoSignals[j]!
        if (!sameAssetOrRelated(a, b)) continue
        const rule = infoChainRules.find((item) => item.matches(a, b))
        if (!rule) continue
        addChain(
          "information_amplification",
          a,
          b,
          rule.impact,
          rule.severity,
          rule.plan(a, b),
          rule.confidence,
        )
      }
    }

    // 1. credential_endpoint: Credential + API endpoint = ATO
    for (const cred of credentials) {
      for (const ep of endpoints) {
        if (!sameAssetOrRelated(cred, ep)) continue
        if (ep.severity === "info") continue
        // A credential-shaped string is not proof of validity or effective access.
        const credentialVerified = cred.status === "exploited"
        const conf = credentialVerified ? 85 : cred.confidenceLevel === "confirmed" ? 45 : 30
        addChain(
          "credential_endpoint",
          cred,
          ep,
          "POTENTIAL_ACCOUNT_ACCESS",
          credentialVerified ? "high" : "medium",
          `In an authorized test account, verify whether "${cred.title}" is valid and whether it grants access to "${ep.title}". Do not try exposed credentials against unrelated users or services; record the actual principal and permissions.`,
          conf,
        )
      }
    }

    // 2. info_disclosure_ssrf: Info disclosure + SSRF-testable endpoint
    for (const info of services) {
      for (const ep of endpoints) {
        if (!sameAssetOrRelated(info, ep)) continue
        const hasSsrf = (checkMap.get(ep.id) ?? []).some((c) => c.category.toLowerCase().includes("ssrf"))
        if (!hasSsrf) continue
        const conf = hasVulnCheck(ep, "ssrf") ? 90 : 55
        addChain(
          "info_disclosure_ssrf",
          info,
          ep,
          "SSRF_TO_INTERNAL",
          "high",
          `Use internal URL/config from "${info.title}" as SSRF target via "${ep.title}"`,
          conf,
        )
      }
    }

    // 3. redirect_oauth: Open redirect + OAuth endpoint
    for (const a of entries) {
      if (!hasVulnCheck(a, "redirect") && !hasVulnCheck(a, "open redirect")) continue
      for (const b of entries) {
        if (a.id === b.id) continue
        if (!sameAssetOrRelated(a, b)) continue
        const text = `${b.title} ${b.detail ?? ""}`
        if (!OAUTH_REGEX.test(text)) continue
        addChain(
          "redirect_oauth",
          a,
          b,
          "TOKEN_THEFT",
          "critical",
          `Chain open redirect from "${a.title}" into OAuth flow at "${b.title}" to steal access_token`,
          80,
        )
      }
    }

    // 4. idor_data_leak: IDOR + user data endpoint
    for (const a of entries) {
      if (!hasVulnCheck(a, "idor")) continue
      for (const b of endpoints) {
        if (a.id === b.id) continue
        if (!sameAssetOrRelated(a, b)) continue
        const text = `${b.title} ${b.detail ?? ""}`
        if (!USER_DATA_REGEX.test(text)) continue
        addChain(
          "idor_data_leak",
          a,
          b,
          "MASS_DATA_LEAK",
          "critical",
          `Use IDOR from "${a.title}" to enumerate user data via "${b.title}"`,
          85,
        )
      }
    }

    // 5. xss_csrf: XSS + state-changing endpoint
    for (const a of entries) {
      if (!hasVulnCheck(a, "xss")) continue
      for (const b of endpoints) {
        if (a.id === b.id) continue
        if (!sameAssetOrRelated(a, b)) continue
        const text = `${b.title} ${b.detail ?? ""}`
        if (!STATE_CHANGE_REGEX.test(text)) continue
        addChain(
          "xss_csrf",
          a,
          b,
          "CSRF_BYPASS",
          "high",
          `Use XSS from "${a.title}" to perform CSRF on state-changing "${b.title}"`,
          75,
        )
      }
    }

    // 6. ssti_rce: SSTI → RCE
    for (const a of entries) {
      if (!hasVulnCheck(a, "ssti")) continue
      addChain(
        "ssti_rce",
        a,
        a,
        "POTENTIAL_SERVER_SIDE_CODE_EXECUTION",
        "high",
        `Safely validate whether SSTI in "${a.title}" can reach server-side code execution; treat RCE as unproven until separate impact evidence exists`,
        60,
      )
    }

    // 7. race_condition_business: Race + payment/transfer
    for (const a of entries) {
      if (!hasVulnCheck(a, "race")) continue
      for (const b of endpoints) {
        if (a.id === b.id) continue
        if (!sameAssetOrRelated(a, b)) continue
        const text = `${b.title} ${b.detail ?? ""}`
        if (!PAYMENT_REGEX.test(text)) continue
        addChain(
          "race_condition_business",
          a,
          b,
          "FINANCIAL_IMPACT",
          "critical",
          `Use race condition from "${a.title}" on financial endpoint "${b.title}" for double-spend/bypass`,
          80,
        )
      }
    }

    // 8. custom: Entries with explicit chainPotential or relatedEntries
    for (const a of entries) {
      if (!a.chainPotential && a.relatedEntries.length === 0) continue
      for (const relId of a.relatedEntries) {
        const b = entries.find((e) => e.id === relId)
        if (!b) continue
        addChain(
          "custom",
          a,
          b,
          "ESCALATION",
          a.severity ?? "medium",
          a.chainPotential ?? `Chain "${a.title}" with "${b.title}"`,
          60,
        )
      }
    }

    chains.sort((a, b) => b.confidence - a.confidence)
    return chains
  }

  // --- Persistence ---

  export function save(sessionID: string, chains: Candidate[]): void {
    // Load existing to preserve status
    const existing = load(sessionID)
    const existingMap = new Map(existing.map((c) => [`${c.pattern}:${[...c.entryIDs].sort().join("+")}`, c]))

    Database.use((db) => {
      // Update candidates in place so FK-linked finding relationships survive re-detection.
      const activeKeys = new Set<string>()
      const now = Date.now()
      for (const chain of chains) {
        const key = `${chain.pattern}:${[...chain.entryIDs].sort().join("+")}`
        activeKeys.add(key)
        const prev = existingMap.get(key)
        const values = {
          pattern: chain.pattern,
          entry_ids: chain.entryIDs as any,
          entry_titles: chain.entryTitles as any,
          assets: chain.assets as any,
          expected_impact: chain.expectedImpact,
          severity: chain.severity,
          testing_plan: chain.testingPlan,
          confidence: chain.confidence,
          detected_at: chain.detectedAt,
        }
        if (prev) {
          db.update(ChainCandidateTable)
            .set({ ...values, status: prev.status ?? chain.status, time_updated: now })
            .where(eq(ChainCandidateTable.id, prev.id))
            .run()
        } else {
          db.insert(ChainCandidateTable)
            .values({
              id: chain.id,
              session_id: sessionID,
              ...values,
              status: chain.status,
              time_created: now,
              time_updated: now,
            })
            .run()
        }
      }

      // Remove only hypotheses that disappeared; linked edges cascade with that candidate.
      for (const prev of existing) {
        const key = `${prev.pattern}:${[...prev.entryIDs].sort().join("+")}`
        if (!activeKeys.has(key)) {
          db.delete(ChainCandidateTable).where(eq(ChainCandidateTable.id, prev.id)).run()
        }
      }
    })
  }

  export function load(sessionID: string): Candidate[] {
    const { rows, links } = Database.use((db) => ({
      rows: db.select().from(ChainCandidateTable).where(eq(ChainCandidateTable.session_id, sessionID)).all(),
      links: db.select().from(ChainFindingLinkTable).where(eq(ChainFindingLinkTable.session_id, sessionID)).all(),
    }))
    const linksByChain = new Map<string, FindingLink[]>()
    for (const row of links) {
      const list = linksByChain.get(row.chain_candidate_id) ?? []
      list.push(toFindingLink(row))
      linksByChain.set(row.chain_candidate_id, list)
    }
    return rows.map((r) => ({
      id: r.id,
      pattern: r.pattern as Pattern,
      entryIDs: (r.entry_ids as string[]) ?? [],
      entryTitles: (r.entry_titles as string[]) ?? [],
      assets: (r.assets as string[]) ?? [],
      expectedImpact: r.expected_impact ?? "",
      severity: r.severity ?? "medium",
      testingPlan: r.testing_plan ?? "",
      status: r.status as Candidate["status"],
      confidence: r.confidence,
      detectedAt: r.detected_at ?? r.time_created,
      findingLinks: linksByChain.get(r.id) ?? [],
    }))
  }

  export function detectAndPersist(sessionID: string): Candidate[] {
    const chains = detect(sessionID)
    save(sessionID, chains)
    return chains
  }

  export interface FindingLink {
    id: string
    chainID: string
    sourceFindingID: string
    targetFindingID: string
    relation: ChainFindingRelation
    createdAt: number
    updatedAt: number
  }

  export type LinkFindingResult =
    | { ok: true; created: boolean; link: FindingLink }
    | { ok: false; reason: "chain_not_found" | "finding_not_found" | "inactive_finding" | "self_link" }

  /**
   * Persist an explicit directed edge between two findings and one chain candidate.
   * Every referenced row must belong to the same session; this relationship does not
   * alter finding triage or chain status.
   */
  export function linkFindings(input: {
    sessionID: string
    chainID: string
    sourceFindingID: string
    targetFindingID: string
    relation: ChainFindingRelation
  }): LinkFindingResult {
    if (input.sourceFindingID === input.targetFindingID) return { ok: false, reason: "self_link" }

    return Database.transaction((db) => {
      const chain = db
        .select({ id: ChainCandidateTable.id })
        .from(ChainCandidateTable)
        .where(and(
          eq(ChainCandidateTable.id, input.chainID),
          eq(ChainCandidateTable.session_id, input.sessionID),
        ))
        .get()
      if (!chain) return { ok: false, reason: "chain_not_found" } as const

      const findings = db
        .select({ id: VulnerabilityTable.id, status: VulnerabilityTable.status })
        .from(VulnerabilityTable)
        .where(and(
          eq(VulnerabilityTable.session_id, input.sessionID),
          inArray(VulnerabilityTable.id, [input.sourceFindingID, input.targetFindingID]),
        ))
        .all()
      if (findings.length !== 2) return { ok: false, reason: "finding_not_found" } as const
      if (findings.some((finding) => finding.status === "duplicate" || finding.status === "false_positive")) {
        return { ok: false, reason: "inactive_finding" } as const
      }

      const conditions = and(
        eq(ChainFindingLinkTable.chain_candidate_id, input.chainID),
        eq(ChainFindingLinkTable.source_vulnerability_id, input.sourceFindingID),
        eq(ChainFindingLinkTable.target_vulnerability_id, input.targetFindingID),
        eq(ChainFindingLinkTable.relation, input.relation),
      )
      const existingLink = db.select().from(ChainFindingLinkTable).where(conditions).get()
      if (existingLink) {
        return { ok: true, created: false, link: toFindingLink(existingLink) } as const
      }

      const now = Date.now()
      const id = Identifier.ascending("chain_finding_link")
      db.insert(ChainFindingLinkTable)
        .values({
          id,
          session_id: input.sessionID,
          chain_candidate_id: input.chainID,
          source_vulnerability_id: input.sourceFindingID,
          target_vulnerability_id: input.targetFindingID,
          relation: input.relation,
          time_created: now,
          time_updated: now,
        })
        .onConflictDoNothing()
        .run()

      const saved = db.select().from(ChainFindingLinkTable).where(conditions).get()
      if (!saved) throw new Error("Chain finding link insert did not persist after conflict handling.")
      return { ok: true, created: saved.id === id, link: toFindingLink(saved) } as const
    })
  }

  export function findingLinks(sessionID: string, chainID: string): FindingLink[] {
    return Database.use((db) =>
      db
        .select()
        .from(ChainFindingLinkTable)
        .where(and(
          eq(ChainFindingLinkTable.session_id, sessionID),
          eq(ChainFindingLinkTable.chain_candidate_id, chainID),
        ))
        .all()
        .map(toFindingLink),
    )
  }

  function toFindingLink(row: typeof ChainFindingLinkTable.$inferSelect): FindingLink {
    return {
      id: row.id,
      chainID: row.chain_candidate_id,
      sourceFindingID: row.source_vulnerability_id,
      targetFindingID: row.target_vulnerability_id,
      relation: row.relation,
      createdAt: row.time_created,
      updatedAt: row.time_updated,
    }
  }

  // --- Prompt Formatting ---

  export function formatForPrompt(chains: Candidate[]): string {
    const active = chains.filter((c) => c.status === "detected" || c.status === "testing")
    if (active.length === 0) return ""

    const lines: string[] = [`## Chain Hypotheses (${active.length} candidates; not confirmed findings)`, "Treat each item as a lead only. Validate every link independently, use an authorized controlled fixture, record a baseline and disconfirming control, and confirm terminal impact before changing finding severity or reporting a chain."]
    for (const c of active.slice(0, 10)) {
      const confLabel = c.confidence >= 80 ? "HIGH" : c.confidence >= 60 ? "MED" : "LOW"
      lines.push(
        `[${confLabel}-${c.confidence}%] chain_id=${c.id} | ${c.pattern.toUpperCase()}: "${c.entryTitles[0]}"${c.entryTitles[1] && c.entryTitles[1] !== c.entryTitles[0] ? ` + "${c.entryTitles[1]}"` : ""} -> ${c.expectedImpact}`,
      )
      lines.push(`  Expected impact (unproven until tested): ${c.expectedImpact} | Candidate severity: ${c.severity}`)
      lines.push(`  Next test: ${c.testingPlan}`)
      lines.push(`  Entries: ${c.entryIDs.join(", ")} | Assets: ${c.assets.join(", ")}`)
      for (const link of c.findingLinks ?? []) {
        lines.push(`  Finding link: ${link.sourceFindingID} --${link.relation}--> ${link.targetFindingID} (relationship recorded; chain impact remains unconfirmed)`)
      }
    }
    return lines.join("\n")
  }
}
