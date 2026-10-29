import { parseRawRequest } from "./normalize/parser"
import { TargetMemory } from "../target"

export type CapturedRequestScopeInput = {
  rawRequest: string
  scheme: "http" | "https"
}

export type CapturedRequestScopeDecision = {
  allowed: boolean
  url?: string
  reason: string
}

/**
 * Resolve and authorize the concrete URL in a captured HTTP request against
 * persisted target scope. Uses the raw request path, not the dedup/template
 * path, so an ID placeholder can never broaden a path-scoped authorization.
 *
 * Captures are untrusted input: they must pass this check before persistence,
 * credential registration, or analyzer/subagent dispatch.
 */
export async function checkCapturedRequestScope(
  request: CapturedRequestScopeInput,
): Promise<CapturedRequestScopeDecision> {
  let candidate: URL
  try {
    const requestLine = request.rawRequest.split(/\r?\n/, 1)[0]?.trim() ?? ""
    const targetMatch = requestLine.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/i)
    if (!targetMatch) {
      return { allowed: false, reason: "captured request could not be parsed into a concrete URL" }
    }
    const target = targetMatch[2]!
    if (/^https?:\/\//i.test(target)) {
      // In proxy/absolute-form requests, the request-target itself is authoritative.
      // Do not let an inconsistent scheme hint or Host header rewrite its origin.
      candidate = new URL(target)
    } else {
      const parsed = parseRawRequest({ raw: request.rawRequest, scheme: request.scheme })
      candidate = new URL(parsed.rawPath, parsed.origin)
    }
  } catch {
    return { allowed: false, reason: "captured request URL is invalid" }
  }

  let decision: Awaited<ReturnType<typeof TargetMemory.checkURLScope>>
  try {
    decision = await TargetMemory.checkURLScope(candidate.href)
  } catch (error) {
    return {
      allowed: false,
      url: candidate.href,
      reason: "persisted scope check failed closed: " + (error instanceof Error ? error.message : String(error)),
    }
  }
  return {
    allowed: decision.allowed && Boolean(decision.workspace),
    url: candidate.href,
    reason: decision.allowed && decision.workspace
      ? "allowed by persisted target scope"
      : decision.reason || "request is not authorized by persisted target scope",
  }
}
