/**
 * Shared policy for adaptive vulnerability verification.
 *
 * This module deliberately separates "attempt budget exhausted" from a
 * false-positive verdict: exhausting the budget can only produce INCONCLUSIVE.
 */
export namespace VerificationAttempts {
  export type Outcome = "confirmed" | "disproven" | "inconclusive"

  export interface Attempt {
    /** Stable strategy identifier, e.g. "idor.owner-vs-non-owner". */
    strategyID: string
    /** Distinguishes meaningful variants of a strategy without counting retries. */
    variantKey: string
    rationale: string
    resultSummary: string
    evidenceRef?: string
    /** True only when this attempt ran under valid preconditions. */
    validConditions: boolean
  }

  export interface HypothesisIdentity {
    asset: string
    endpoint?: string
    vulnerabilityClass: string
  }

  function normalizeAssetIdentity(value: string): string {
    const trimmed = value.trim()
    // URL hosts are case-insensitive, but URL paths and query values may not be.
    // Never lowercase a whole URL: /Admin and /admin can be different assets.
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed
    try {
      const url = new URL(trimmed)
      return url.href
    } catch {
      return trimmed
    }
  }

  /** A hypothesis key cannot mix evidence across different endpoints or vulnerability classes. */
  export function sameHypothesisIdentity(a: HypothesisIdentity, b: HypothesisIdentity): boolean {
    return normalizeAssetIdentity(a.asset) === normalizeAssetIdentity(b.asset) &&
      (a.endpoint?.trim() ?? "") === (b.endpoint?.trim() ?? "") &&
      a.vulnerabilityClass.trim().toLowerCase() === b.vulnerabilityClass.trim().toLowerCase()
  }

  /** Confirmed/disproven hypotheses are terminal and cannot accept more attempts. */
  export function isTerminalOutcome(outcome: Outcome | undefined): boolean {
    return outcome === "confirmed" || outcome === "disproven"
  }

  export interface DecisionInput {
    attempts: Attempt[]
    /** Evidence directly supports the stated vulnerability hypothesis. */
    decisiveConfirmation?: boolean
    /** Evidence directly contradicts the stated hypothesis under valid conditions. */
    decisiveDisproof?: boolean
    /** Durable reference to the direct request/response evidence that justifies either verdict. */
    decisiveEvidenceRef?: string
    /** A hard stop such as out-of-scope, unsafe, or unavailable target. */
    blockedReason?: string
  }

  export interface Decision {
    outcome: Outcome
    attemptsUsed: number
    remainingAttempts: null
    canContinue: boolean
    reason: string
  }

  /** Identity includes the variant: exact retries never consume the budget. */
  export function attemptKey(attempt: Pick<Attempt, "strategyID" | "variantKey">): string {
    return `${attempt.strategyID.trim().toLowerCase()}::${attempt.variantKey.trim().toLowerCase()}`
  }

  export function uniqueAttempts<T extends Attempt>(attempts: T[]): T[] {
    const seen = new Set<string>()
    return attempts.filter((attempt) => {
      const key = attemptKey(attempt)
      if (!attempt.strategyID.trim() || !attempt.variantKey.trim() || seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  /** Only valid attempts with durable evidence can consume the verification budget. */
  export function isEvidenceBackedValidAttempt(attempt: Attempt): boolean {
    return attempt.validConditions && Boolean(attempt.evidenceRef?.trim())
  }

  export function canRunAttempt(attempts: Attempt[], next: Pick<Attempt, "strategyID" | "variantKey">): boolean {
    const unique = uniqueAttempts(attempts)
    const validAttemptCount = unique.filter(isEvidenceBackedValidAttempt).length
    return Boolean(next.strategyID.trim() && next.variantKey.trim()) &&
      !unique.some((attempt) => attemptKey(attempt) === attemptKey(next))
  }

  export function decide(input: DecisionInput): Decision {
    const attempts = uniqueAttempts(input.attempts)
    // Count only unique attempts with valid preconditions and durable evidence.
    // Counts are informational; they are not an arbitrary ceiling or verdict threshold.
    const attemptsUsed = attempts.filter(isEvidenceBackedValidAttempt).length
    const remainingAttempts = null

    // Hard stops (scope, safety, or unavailable target) always win over verdicts.
    if (input.blockedReason) {
      return { outcome: "inconclusive", attemptsUsed, remainingAttempts, canContinue: false, reason: input.blockedReason }
    }

    const hasDecisiveEvidence = Boolean(input.decisiveEvidenceRef?.trim())

    if (input.decisiveConfirmation && hasDecisiveEvidence && attempts[attempts.length - 1] && isEvidenceBackedValidAttempt(attempts[attempts.length - 1]!)) {
      return { outcome: "confirmed", attemptsUsed, remainingAttempts, canContinue: false, reason: "Decisive evidence supports the vulnerability hypothesis." }
    }

    const hasValidDisproof = Boolean(
      input.decisiveDisproof &&
      hasDecisiveEvidence &&
      attempts[attempts.length - 1] &&
      isEvidenceBackedValidAttempt(attempts[attempts.length - 1]!),
    )
    if (hasValidDisproof) {
      return {
        outcome: "disproven",
        attemptsUsed,
        remainingAttempts,
        canContinue: false,
        reason: "Direct evidence contradicts the stated hypothesis under valid test conditions.",
      }
    }

    return { outcome: "inconclusive", attemptsUsed, remainingAttempts, canContinue: true, reason: "The hypothesis remains unresolved; continue only while a materially distinct, evidence-producing check can change the conclusion." }
  }
}
