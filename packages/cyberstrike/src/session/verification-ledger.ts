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

    if (input.decisiveResult === "confirmed" && (!input.attempt.validConditions || !input.attempt.evidenceRef?.trim())) {
      throw new Error("A decisive confirmed verdict requires valid_conditions=true and evidence_ref")
    }
    if (input.decisiveResult === "disproven" && (!input.attempt.validConditions || !input.attempt.evidenceRef?.trim())) {
      throw new Error("A disproven verdict requires valid_conditions=true and evidence_ref")
    }

    // Keep identity checks, attempt-budget enforcement, insertion, and verdict
    // updates atomic so concurrent sessions/processes cannot bypass ledger invariants.
    return Database.transaction(() => {
      const before = list({ sessionID, hypothesisKey })
      // A hypothesis key is the identity boundary for one claim. Mixing assets or
      // vulnerability classes under the same key corrupts attempt counts and can
      // make evidence from one target influence a verdict for another.
      const identityConflict = before.find((item) =>
        !Policy.sameHypothesisIdentity(item, input),
      )
      if (identityConflict) {
        throw new Error(
          `hypothesis_key "${hypothesisKey}" is already bound to a different asset, endpoint, or vulnerability class; use a separate key for a distinct claim.`,
        )
      }
      const priorOutcome = before[before.length - 1]?.outcome
      if (Policy.isTerminalOutcome(priorOutcome)) {
        throw new Error(`This hypothesis is already ${priorOutcome}; terminal hypotheses cannot accept more attempts. Start a new hypothesis_key only for a genuinely different claim.`)
      }
      const key = Policy.attemptKey(input.attempt)
      const existing = before.find((item) => Policy.attemptKey(item) === key)
      if (before.length >= Policy.MAX_ATTEMPTS && !existing) {
        throw new Error("The 20-distinct-attempt budget is exhausted. Do not create attempt 21; use action=status and preserve unresolved cases as INCONCLUSIVE / NEEDS REVIEW.")
      }
      let duplicate = Boolean(existing)
      let recorded: Attempt

      if (existing) {
        // A duplicate does not consume budget, but refresh its observed evidence so
        // a corrected session/precondition result is not hidden by an older failure.
        Database.use((db) => db.update(VerificationAttemptTable).set({
          result_summary: input.attempt.resultSummary,
          evidence_ref: input.attempt.evidenceRef ?? null,
          valid_conditions: input.attempt.validConditions ? 1 : 0,
          time_updated: Date.now(),
        }).where(eq(VerificationAttemptTable.id, existing.id)).run())
        recorded = {
          ...existing,
          resultSummary: input.attempt.resultSummary,
          evidenceRef: input.attempt.evidenceRef,
          validConditions: input.attempt.validConditions,
        }
      } else {
        const now = Date.now()
        const id = Identifier.ascending("verification_attempt")
        Database.use((db) => db.insert(VerificationAttemptTable).values({
          id,
          session_id: sessionID,
          hypothesis_key: hypothesisKey,
          asset: input.asset,
          endpoint: input.endpoint ?? null,
          vulnerability_class: input.vulnerabilityClass,
          strategy_id: input.attempt.strategyID.trim().toLowerCase(),
          variant_key: input.attempt.variantKey.trim().toLowerCase(),
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
      // Put the evidence-bearing attempt last for the policy's precondition gate,
      // without changing the distinct-attempt count.
      const decisionAttempts = [
        ...all.filter((item) => Policy.attemptKey(item) !== key),
        input.attempt,
      ]
      const decision = Policy.decide({
        attempts: decisionAttempts,
        decisiveConfirmation: input.decisiveResult === "confirmed" && Boolean(input.attempt.evidenceRef?.trim()),
        decisiveDisproof: input.decisiveResult === "disproven" && input.attempt.validConditions && Boolean(input.attempt.evidenceRef?.trim()),
        decisiveEvidenceRef: input.attempt.evidenceRef,
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
    })
  }
}
