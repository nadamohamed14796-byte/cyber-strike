import { Database, eq, and, asc } from "../storage/db"
import { VerificationAttemptTable } from "../methodology/methodology.sql"
import { Identifier } from "../id/id"
import { Session } from "./index"
import { VerificationAttempts as Policy } from "../methodology/verification-attempts"

export namespace VerificationLedger {
  export type Attempt = Policy.Attempt & {
    id: string
    sessionID: string
    hypothesisKey: string
    asset: string
    endpoint?: string
    vulnerabilityClass: string
    outcome: Policy.Outcome
    timeCreated: number
  }

  export function list(input: { sessionID: string; hypothesisKey: string }): Attempt[] {
    const sessionID = Session.root(input.sessionID)
    const rows = Database.use((db) =>
      db.select().from(VerificationAttemptTable)
        .where(and(
          eq(VerificationAttemptTable.session_id, sessionID),
          eq(VerificationAttemptTable.hypothesis_key, input.hypothesisKey),
        ))
        .orderBy(asc(VerificationAttemptTable.time_created))
        .all(),
    )
    return rows.map((row) => ({
      id: row.id,
      sessionID: row.session_id,
      hypothesisKey: row.hypothesis_key,
      asset: row.asset,
      endpoint: row.endpoint ?? undefined,
      vulnerabilityClass: row.vulnerability_class,
      strategyID: row.strategy_id,
      variantKey: row.variant_key,
      rationale: row.rationale,
      resultSummary: row.result_summary,
      evidenceRef: row.evidence_ref ?? undefined,
      validConditions: row.valid_conditions === 1,
      outcome: (row.outcome as Policy.Outcome) ?? "inconclusive",
      timeCreated: row.time_created,
    }))
  }

  export function record(input: {
    sessionID: string
    hypothesisKey: string
    asset: string
    endpoint?: string
    vulnerabilityClass: string
    attempt: Policy.Attempt
    decisiveResult?: "none" | "confirmed" | "disproven"
    blockedReason?: string
  }): { attempt: Attempt; decision: Policy.Decision; duplicate: boolean } {
    const sessionID = Session.root(input.sessionID)
    const hypothesisKey = input.hypothesisKey.trim()
    if (!hypothesisKey) throw new Error("hypothesis_key must not be empty")
    if (!input.asset.trim() || !input.vulnerabilityClass.trim()) {
      throw new Error("asset and vulnerability_class must not be empty")
    }
    if (!input.attempt.strategyID.trim() || !input.attempt.variantKey.trim()) {
      throw new Error("strategy_id and variant_key must not be empty")
    }

    if (input.decisiveResult === "confirmed" && !input.attempt.evidenceRef?.trim()) {
      throw new Error("A decisive confirmed verdict requires evidence_ref")
    }
    if (input.decisiveResult === "disproven" && (!input.attempt.validConditions || !input.attempt.evidenceRef?.trim())) {
      throw new Error("A disproven verdict requires valid_conditions=true and evidence_ref")
    }

    const before = list({ sessionID, hypothesisKey })
    const key = Policy.attemptKey(input.attempt)
    const existing = before.find((item) => Policy.attemptKey(item) === key)
    let duplicate = Boolean(existing)
    let recorded: Attempt

    if (existing) {
      recorded = existing
    } else {
      if (before.length >= Policy.MAX_ATTEMPTS) {
        const decision = Policy.decide({ attempts: before, blockedReason: "The 20-distinct-attempt budget is exhausted; verdict remains inconclusive." })
        return { attempt: before[before.length - 1], decision, duplicate: false }
      }
      const now = Date.now()
      const id = Identifier.ascending("verification_attempt")
      Database.use((db) => db.insert(VerificationAttemptTable).values({
        id,
        session_id: sessionID,
        hypothesis_key: hypothesisKey,
        asset: input.asset,
        endpoint: input.endpoint ?? null,
        vulnerability_class: input.vulnerabilityClass,
        strategy_id: input.attempt.strategyID.trim(),
        variant_key: input.attempt.variantKey.trim(),
        rationale: input.attempt.rationale,
        result_summary: input.attempt.resultSummary,
        evidence_ref: input.attempt.evidenceRef ?? null,
        valid_conditions: input.attempt.validConditions ? 1 : 0,
        outcome: "inconclusive",
        time_created: now,
        time_updated: now,
      }).run())
      recorded = {
        ...input.attempt, id, sessionID, hypothesisKey, asset: input.asset,
        endpoint: input.endpoint, vulnerabilityClass: input.vulnerabilityClass, outcome: "inconclusive", timeCreated: now,
      }
    }

    const all = list({ sessionID, hypothesisKey })
    const decision = Policy.decide({
      attempts: all,
      decisiveConfirmation: input.decisiveResult === "confirmed" && Boolean(input.attempt.evidenceRef?.trim()),
      decisiveDisproof: input.decisiveResult === "disproven" && Boolean(input.attempt.evidenceRef?.trim()),
      blockedReason: input.blockedReason,
    })
    Database.use((db) => db.update(VerificationAttemptTable).set({
      outcome: decision.outcome,
      time_updated: Date.now(),
    }).where(and(
      eq(VerificationAttemptTable.session_id, sessionID),
      eq(VerificationAttemptTable.hypothesis_key, hypothesisKey),
    )).run())
    return { attempt: recorded, decision, duplicate }
  }
}
