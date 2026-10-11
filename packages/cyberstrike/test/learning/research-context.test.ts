import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { ResearchContext, researchClassForSignalTags } from "../../src/learning/research-context"
import { tmpdir } from "../fixture/fixture"

test("global research retrieval guidance is available even before target signals exist", async () => {
  await using dir = await tmpdir()
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const context = ResearchContext.generate("ses_research_baseline_test")
      expect(context).toContain("Global Research Memory — Signal-Triggered Use")
      expect(context).toContain("shared across agents and targets")
      expect(context).toContain("research_knowledge")
      expect(context).toContain("not evidence about the current target")
      expect(context).toContain("never copy them as the current target")
      expect(context).toContain("correlate_javascript")
      expect(context).toContain("javascript/ directory")
      expect(context).toContain("target_note")
      await Instance.dispose()
    },
  })
})

test("request-derived global research signals are pattern-based and do not assert a vulnerability", async () => {
  const { requestResearchSignals } = await import("../../src/learning/research-context")
  expect(requestResearchSignals({ method: "GET", path: "/api/v2/orders/123", contentType: "application/json", status: 403 })).toEqual(
    expect.arrayContaining(["api-endpoint", "authorization-boundary", "object-identifier"]),
  )
  expect(requestResearchSignals({ method: "POST", path: "/checkout", contentType: "application/json", status: 200 })).toEqual(
    expect.arrayContaining(["api-endpoint", "business-logic"]),
  )
  expect(requestResearchSignals({ method: "GET", path: "/about", contentType: "text/html", status: 200 })).not.toContain("authorization-boundary")
  // Numeric object IDs are a retrieval signal even when the response is 200;
  // this does not establish that authorization is broken.
  expect(requestResearchSignals({ method: "GET", path: "/users/123", contentType: "application/json", status: 200 })).toContain("object-identifier")
})

test("request-derived research signals cover JavaScript, auth, uploads, and URL-fetching surfaces without asserting findings", async () => {
  const { requestResearchSignals } = await import("../../src/learning/research-context")
  expect(requestResearchSignals({ method: "GET", path: "/assets/app.js", contentType: "application/javascript", status: 200 })).toEqual(
    expect.arrayContaining(["javascript-client"]),
  )
  expect(requestResearchSignals({ method: "GET", path: "/assets/app.js.map", contentType: "application/json", status: 200 })).toEqual(
    expect.arrayContaining(["javascript-client", "source-map"]),
  )
  expect(requestResearchSignals({ method: "POST", path: "/oauth/callback", contentType: "application/json", status: 302 })).toEqual(
    expect.arrayContaining(["authentication-flow", "token-or-jwt"]),
  )
  expect(requestResearchSignals({ method: "POST", path: "/files/upload", contentType: "multipart/form-data", status: 200 })).toEqual(
    expect.arrayContaining(["file-upload", "business-logic"]),
  )
  expect(requestResearchSignals({ method: "POST", path: "/webhook/import-url", contentType: "application/json", status: 200 })).toEqual(
    expect.arrayContaining(["server-side-request", "business-logic"]),
  )
  expect(requestResearchSignals({ method: "GET", path: "/assets/app.js", contentType: "application/javascript", status: 200 })).not.toContain("idor")
})

test("explicit user request produces bounded global retrieval tags without retaining request text", () => {
  const { promptResearchSignals } = require("../../src/learning/research-context") as typeof import("../../src/learning/research-context")
  expect(promptResearchSignals("Please investigate whether the order ID has an IDOR issue in the API and compare owner/non-owner behavior")).toEqual(
    expect.arrayContaining(["idor", "object-identifier", "api-endpoint"]),
  )
  expect(promptResearchSignals("ordinary copywriting task with no security signal")).toEqual([])
  expect(promptResearchSignals("JWT OAuth refresh token login session")).toEqual(
    expect.arrayContaining(["authentication-flow", "token-or-jwt"]),
  )
})

test("maps request patterns to broad research classes without treating them as findings", () => {
  expect(researchClassForSignalTags(["object-identifier"])).toBe("idor")
  expect(researchClassForSignalTags(["authorization-boundary"])).toBe("access-control")
  expect(researchClassForSignalTags(["server-side-request"])).toBe("ssrf")
  expect(researchClassForSignalTags(["javascript-client"])).toBeUndefined()
})
