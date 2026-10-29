import { TargetMemory } from "../target"

export type CapturedRequestScopeInput = {
  origin?: string | null
  normalizedPath: string
}

export type CapturedRequestScopeDecision = {
  allowed: boolean
  url?: string
  reason: string
}

/**
 * Resolve and authorize a captured HTTP request against persisted target scope.
 * Captures are untrusted input: they must pass this check before persistence,
 * credential registration, or analyzer/subagent dispatch.
 */
export async function checkCapturedRequestScope(
  request: CapturedRequestScopeInput,
): Promise<CapturedRequestScopeDecision> {
  if (!request.origin) {
    return {
      allowed: false,
      reason: "captured request has no unambiguous origin; cannot verify persisted scope",
    }
  }

  let candidate: URL
  try {
    candidate = new URL(request.normalizedPath, request.origin)
  } catch {
    return { allowed: false, reason: "captured request URL is invalid" }
  }

  const decision = await TargetMemory.checkURLScope(candidate.href)
  return {
    allowed: decision.allowed && Boolean(decision.workspace),
    url: candidate.href,
    reason: decision.allowed && decision.workspace
      ? "allowed by persisted target scope"
      : decision.reason || "request is not authorized by persisted target scope",
  }
}
