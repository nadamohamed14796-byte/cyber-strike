import { expect, test } from "bun:test"
import {
  assertTaskResumeScope,
  isInternalImpactHandoff,
  requestIDFromPromptText,
  requestIDFromRecentPromptTexts,
  selectTaskRequestContext,
  shouldInferSessionRequestID,
  proxyTesterMethodologyBlock,
  proxyTesterMethodologyPhase,
} from "../../src/tool/task-resume"

test("resumes only a subtask owned by the current parent session", () => {
  expect(() => assertTaskResumeScope({ id: "child-1", parentID: "parent-1" }, "parent-1")).not.toThrow()
  expect(() => assertTaskResumeScope({ id: "child-1", parentID: "other-parent" }, "parent-1")).toThrow(
    "Cannot resume task child-1: it does not belong to the current parent session.",
  )
  expect(() => assertTaskResumeScope({ id: "root-session", parentID: null }, "parent-1")).toThrow()
})

test("Proxy Agent keeps request-ID inference in standalone and delegated modes", () => {
  expect(shouldInferSessionRequestID({ name: "proxy-agent", mode: "all" })).toBe(true)
  expect(shouldInferSessionRequestID({ name: "proxy-agent", mode: "primary" })).toBe(true)
  expect(shouldInferSessionRequestID({ name: "proxy-agent", mode: "subagent" })).toBe(true)
  expect(shouldInferSessionRequestID({ name: "proxy-analyzer", mode: "subagent" })).toBe(true)
  expect(shouldInferSessionRequestID({ name: "cyberstrike", mode: "primary" })).toBe(false)
  expect(shouldInferSessionRequestID(undefined)).toBe(false)
})

test("only non-Impact-Hunter callers can use the background Impact Hunter handoff bypass", () => {
  const base = {
    subagentType: "impact-hunter",
    background: true,
    caller: "proxy-tester-xss",
    callerMode: "subagent" as const,
  }
  expect(isInternalImpactHandoff(base)).toBe(true)
  expect(isInternalImpactHandoff({ ...base, caller: "proxy-agent", callerMode: "all" })).toBe(true)
  expect(isInternalImpactHandoff({ ...base, caller: "cyberstrike", callerMode: "primary" })).toBe(true)
  expect(isInternalImpactHandoff({ ...base, background: false })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, subagentType: "proxy-tester-idor" })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, caller: "impact-hunter" })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, caller: undefined })).toBe(false)
  expect(isInternalImpactHandoff({ ...base, callerMode: undefined })).toBe(false)
})


test("an explicit request ID never falls back to a different request", () => {
  const requests = [
    { id: "req-old", status: "processed", time: { updated: 10 } },
    { id: "req-active", status: "processing", time: { updated: 20 } },
  ]
  expect(selectTaskRequestContext(requests, "req-old").request?.id).toBe("req-old")
  expect(selectTaskRequestContext(requests, "req-missing")).toEqual({ reason: "request_not_found" })
})

test("implicit context chooses the oldest queued request when the broker is between turns", () => {
  const requests = [
    { id: "request-01", status: "queued", time: { updated: 10 } },
    { id: "request-10", status: "queued", time: { updated: 100 } },
    { id: "request-02", status: "queued", time: { updated: 20 } },
  ]
  expect(selectTaskRequestContext(requests).request?.id).toBe("request-01")
})

test("implicit request context is inferred only when unambiguous", () => {
  const requests = [
    { id: "req-finished", status: "processed", time: { updated: 30 } },
    { id: "req-active", status: "processing", time: { updated: 20 } },
  ]
  expect(selectTaskRequestContext(requests).request?.id).toBe("req-active")
  expect(selectTaskRequestContext([
    ...requests,
    { id: "req-active-2", status: "processing", time: { updated: 40 } },
  ])).toEqual({ reason: "ambiguous_processing_requests" })
})


test("request identity parser reads only known identity sections", () => {
  expect(requestIDFromPromptText([
    "## Request Task Identity",
    "- Request ID: req-captured-1",
    "- Method: POST",
    "## Required Evidence-Driven Analysis",
    "Request ID: decoy-without-list-marker",
  ].join("\n"))).toBe("req-captured-1")

  expect(requestIDFromPromptText([
    "Unrelated text mentioning Request ID: not-an-identity",
    "## Current request",
    "- request_id: req-nested-2",
    "- method: GET",
    "## Credential Context",
  ].join("\n"))).toBe("req-nested-2")

  expect(requestIDFromPromptText("Request ID: not-in-a-known-section")).toBeUndefined()
  expect(requestIDFromPromptText("## Request Task Identity\n- Method: GET")).toBeUndefined()
})

test("persistent broker request identity follows the latest captured turn", () => {
  const first = ["## Request Task Identity", "- Request ID: req-first", "- Method: GET"].join("\n")
  const second = ["## Request Task Identity", "- Request ID: req-second", "- Method: POST"].join("\n")
  const followUp = "Please explain the previous result without starting a new capture."

  expect(requestIDFromRecentPromptTexts([first, second])).toBe("req-second")
  // A follow-up with no identity block continues the most recent capture.
  expect(requestIDFromRecentPromptTexts([first, second, followUp])).toBe("req-second")
  expect(requestIDFromRecentPromptTexts([followUp])).toBeUndefined()
})

test("proxy tester IDs map to existing methodology phases and blocked phases stop dispatch", () => {
  const mappings = [
    ["proxy-tester-idor", "authorization_testing"],
    ["proxy-tester-authz", "authorization_testing"],
    ["proxy-tester-authn", "authentication_testing"],
    ["proxy-tester-injection", "input_validation"],
    ["proxy-tester-file-attacks", "input_validation"],
    ["proxy-tester-business-logic", "business_logic"],
    ["proxy-tester-mass-assignment", "api_security"],
    ["proxy-tester-ssrf", "api_security"],
    ["proxy-tester-llm", "api_security"],
  ] as const

  for (const [agentID, phaseID] of mappings) {
    expect(proxyTesterMethodologyPhase(agentID)).toBe(phaseID)
    expect(
      proxyTesterMethodologyBlock(agentID, [{ id: phaseID, status: "blocked", blockReason: "upstream evidence missing" }]),
    ).toEqual({ phase: phaseID, reason: "upstream evidence missing" })
    expect(proxyTesterMethodologyBlock(agentID, [{ id: phaseID, status: "not_started" }])).toBeUndefined()
  }

  expect(proxyTesterMethodologyPhase("proxy-tester-idOR")).toBeUndefined()
  expect(proxyTesterMethodologyBlock("proxy-analyzer", [{ id: "authorization_testing", status: "blocked" }])).toBeUndefined()
  expect(
    proxyTesterMethodologyBlock("proxy-tester-idor", [{ id: "scope_analysis", status: "completed" }]),
  ).toEqual({
    phase: "authorization_testing",
    reason: "This testing phase is not applicable to the current target scope or has not been initialized.",
  })
})
