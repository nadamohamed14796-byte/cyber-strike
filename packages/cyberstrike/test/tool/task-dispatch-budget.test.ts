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

test("caps automatic specialist fan-out at two independent lanes per request", () => {
  const children = [
    { id: "ses_idor", title: "Ownership check [request:req_three] [agent:proxy-tester-idor]" },
    { id: "ses_authz", title: "Access boundary check [request:req_three] [agent:proxy-tester-authz]" },
  ]
  const result = evaluateProxyRequestDispatch({
    requestID: "req_three",
    agentID: "proxy-tester-injection",
    children,
  })
  expect(result).toEqual({
    allowed: false,
    reason: "specialist_budget",
    existingSpecialists: ["proxy-tester-authz", "proxy-tester-idor"],
  })
})

test("counts in-flight reservations so concurrent model tool calls cannot exceed the budget", () => {
  const result = evaluateProxyRequestDispatch({
    requestID: "req_four",
    agentID: "proxy-tester-injection",
    children: [],
    reservedAgentIDs: ["proxy-tester-idor", "proxy-tester-authz"],
  })
  expect(result.allowed).toBe(false)
  if (!result.allowed) expect(result.reason).toBe("specialist_budget")
})

test("allows one analyzer plus up to two specialist lanes", () => {
  const result = evaluateProxyRequestDispatch({
    requestID: "req_five",
    agentID: "proxy-tester-idor",
    children: [
      { id: "ses_analyzer", title: "Endpoint analysis [request:req_five] [agent:proxy-analyzer]" },
    ],
  })
  expect(result).toEqual({ allowed: true })
})
