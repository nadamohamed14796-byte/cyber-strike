import { expect, test } from "bun:test"
import { evaluateProxyRequestDispatch } from "../../src/tool/task-dispatch-budget"

test("reuses an existing specialist for the same request instead of dispatching it twice", () => {
  const result = evaluateProxyRequestDispatch({
    requestID: "req_one",
    agentID: "proxy-tester-idor",
    children: [
      { id: "ses_existing", title: "Check owner boundary (@proxy-tester-idor subagent) [request:req_one] [agent:proxy-tester-idor]" },
    ],
  })
  expect(result).toEqual({ allowed: false, reason: "duplicate", existingTaskID: "ses_existing" })
})

test("blocks a second concurrent dispatch of the same specialist lane", () => {
  const result = evaluateProxyRequestDispatch({
    requestID: "req_inflight",
    agentID: "proxy-tester-idor",
    children: [],
    reservedAgentIDs: ["proxy-tester-idor"],
  })
  expect(result).toEqual({ allowed: false, reason: "duplicate" })
})

test("allows the same specialist for a different captured request", () => {
  const result = evaluateProxyRequestDispatch({
    requestID: "req_two",
    agentID: "proxy-tester-idor",
    children: [
      { id: "ses_existing", title: "Check owner boundary (@proxy-tester-idor subagent) [request:req_one] [agent:proxy-tester-idor]" },
    ],
  })
  expect(result).toEqual({ allowed: true })
})

test("allows every independently supported specialist lane after earlier lanes complete", () => {
  const children = [
    { id: "ses_idor", title: "Ownership check [request:req_three] [agent:proxy-tester-idor]" },
    { id: "ses_authz", title: "Access boundary check [request:req_three] [agent:proxy-tester-authz]" },
    { id: "ses_injection", title: "Injection sink check [request:req_three] [agent:proxy-tester-injection]" },
    { id: "ses_ssrf", title: "SSRF destination check [request:req_three] [agent:proxy-tester-ssrf]" },
  ]
  const remaining = [
    "proxy-tester-mass-assignment",
    "proxy-tester-authn",
    "proxy-tester-business-logic",
    "proxy-tester-file-attacks",
    "proxy-tester-llm",
  ]

  for (const agentID of remaining) {
    expect(evaluateProxyRequestDispatch({ requestID: "req_three", agentID, children })).toEqual({ allowed: true })
  }
})

test("allows distinct in-flight reservations while rejecting the same reserved lane", () => {
  const reservations = ["proxy-tester-idor", "proxy-tester-authz"]

  expect(evaluateProxyRequestDispatch({
    requestID: "req_four",
    agentID: "proxy-tester-injection",
    children: [],
    reservedAgentIDs: reservations,
  })).toEqual({ allowed: true })

  expect(evaluateProxyRequestDispatch({
    requestID: "req_four",
    agentID: "proxy-tester-idor",
    children: [],
    reservedAgentIDs: reservations,
  })).toEqual({ allowed: false, reason: "duplicate" })
})

test("allows one analyzer plus all distinct specialist lanes", () => {
  const children = [
    { id: "ses_analyzer", title: "Endpoint analysis [request:req_five] [agent:proxy-analyzer]" },
    { id: "ses_idor", title: "Ownership check [request:req_five] [agent:proxy-tester-idor]" },
    { id: "ses_authz", title: "Access check [request:req_five] [agent:proxy-tester-authz]" },
  ]
  expect(evaluateProxyRequestDispatch({
    requestID: "req_five",
    agentID: "proxy-tester-llm",
    children,
  })).toEqual({ allowed: true })
})

test("allows analyzer dispatch after specialist lanes without counting it as a tester", () => {
  const children = [
    { id: "ses_idor", title: "Ownership check [request:req_six] [agent:proxy-tester-idor]" },
    { id: "ses_authz", title: "Access check [request:req_six] [agent:proxy-tester-authz]" },
    { id: "ses_injection", title: "Injection check [request:req_six] [agent:proxy-tester-injection]" },
  ]
  expect(evaluateProxyRequestDispatch({
    requestID: "req_six",
    agentID: "proxy-analyzer",
    children,
  })).toEqual({ allowed: true })
})
