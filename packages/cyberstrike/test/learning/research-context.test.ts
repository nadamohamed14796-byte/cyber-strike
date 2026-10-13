import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Database } from "../../src/storage/db"
import { RequestTable, SessionTable } from "../../src/session/session.sql"
import { ReportKnowledge } from "../../src/learning/report-knowledge"
import { ResearchContext, promptResearchSignals, researchClassForSignalTags } from "../../src/learning/research-context"
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
  expect(requestResearchSignals({
    method: "GET",
    path: "/api/profile",
    contentType: "application/json",
    status: 200,
    responseHeaders: {
      "Cache-Control": "private, no-store",
      "Access-Control-Allow-Origin": "https://app.example.test",
      "Set-Cookie": "session=must-not-be-used-as-a-signal",
    },
  })).toEqual(expect.arrayContaining(["cache-behavior", "cors-policy"]))
  expect(requestResearchSignals({ method: "GET", path: "/assets/app.js", contentType: "application/javascript", status: 200 })).not.toContain("idor")
})

test("explicit user request produces bounded global retrieval tags without retaining request text", () => {
  expect(promptResearchSignals("Please investigate whether the order ID has an IDOR issue in the API and compare owner/non-owner behavior")).toEqual(
    expect.arrayContaining(["idor", "object-identifier", "api-endpoint"]),
  )
  expect(promptResearchSignals("ordinary copywriting task with no security signal")).toEqual([])
  expect(promptResearchSignals("JWT OAuth refresh token login session")).toEqual(
    expect.arrayContaining(["authentication-flow", "token-or-jwt"]),
  )
  expect(promptResearchSignals("CORS security misconfiguration and information disclosure")).toEqual(
    expect.arrayContaining(["cors-policy", "security-misconfiguration", "information-disclosure"]),
  )
  expect(promptResearchSignals("mass-assignment, NoSQL injection, host header injection, MFA bypass, rate-limit bypass, WebSocket, SAML")).toEqual(
    expect.arrayContaining(["mass-assignment", "nosqli", "host-header-injection", "mfa-bypass", "rate-limit-bypass", "websocket", "saml"]),
  )
})

test("maps request patterns to broad research classes without treating them as findings", () => {
  expect(researchClassForSignalTags(["object-identifier"])).toBe("idor")
  expect(researchClassForSignalTags(["authorization-boundary"])).toBe("access-control")
  expect(researchClassForSignalTags(["server-side-request"])).toBe("ssrf")
  expect(researchClassForSignalTags(["cache-behavior"])).toBe("web-cache")
  expect(researchClassForSignalTags(["cors-policy"])).toBe("cors")
  expect(researchClassForSignalTags(["information-disclosure"])).toBe("information-disclosure")
  expect(researchClassForSignalTags(["security-misconfiguration"])).toBe("security-misconfiguration")
  expect(researchClassForSignalTags(["mass-assignment"])).toBe("mass-assignment")
  expect(researchClassForSignalTags(["nosqli"])).toBe("nosqli")
  expect(researchClassForSignalTags(["host-header-injection"])).toBe("host-header-injection")
  expect(researchClassForSignalTags(["mfa-bypass"])).toBe("mfa-bypass")
  expect(researchClassForSignalTags(["rate-limit-bypass"])).toBe("rate-limit-bypass")
  expect(researchClassForSignalTags(["javascript-client"])).toBeUndefined()
})

test("explicit current research intent is not starved by recent generic API traffic", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_research_priority_" + marker
      const now = Date.now()
      Database.use((db) =>
        db.insert(SessionTable).values({
          id: sessionID,
          project_id: Instance.project.id,
          slug: "research-priority",
          directory: dir.path,
          title: "Research priority test",
          version: "1",
          time_created: now,
          time_updated: now,
        }).run(),
      )

      // Populate enough recent generic API signals to exhaust the context's
      // recommendation budget if the explicit user request is processed last.
      Database.use((db) =>
        db.insert(RequestTable).values(
          Array.from({ length: 12 }, (_, index) => ({
            id: "req_" + marker + "_" + index,
            session_id: sessionID,
            method: "GET",
            normalized_path: "/api/v1/metrics-" + index,
            status: "complete",
            response_status: 200,
            response_content_type: "application/json",
            time_created: now + index,
            time_updated: now + index,
          })),
        ).run(),
      )

      for (let index = 0; index < 6; index++) {
        ReportKnowledge.ingestExternalDetailed({
          title: "Generic API endpoint note " + marker + " " + index,
          severity: "unknown",
          sourceURL: "https://research.example.test/" + marker + "/api-note-" + index,
          lesson: "Map observed API routes and record their response behavior.",
          sourceTrust: 80,
          tags: ["api-endpoint"],
          metadata: { source_trust: 80, extracted: { retrieval_signals: ["api-endpoint"] } },
        })
      }
      const explicitTitle = "Explicit IDOR verification method " + marker
      const explicit = ReportKnowledge.ingestExternalDetailed({
        title: explicitTitle,
        severity: "unknown",
        vulnerabilityClass: "idor",
        sourceURL: "https://research.example.test/" + marker + "/idor-method",
        lesson: "Compare the owner baseline with the same request from a second controlled account.",
        sourceTrust: 90,
        tags: ["idor", "object-identifier", "authorization-boundary"],
        metadata: { source_trust: 90, extracted: { retrieval_signals: ["idor", "object-identifier"] } },
      })
      expect(explicit).not.toBeNull()

      const context = ResearchContext.generate(
        sessionID,
        "Please investigate IDOR and object-level authorization in the API; compare owner-account and non-owner behavior",
      )
      expect(context).toContain(explicitTitle)
      expect(context).toContain("Knowledge record ID: " + explicit?.id)
      expect(context).toContain("Compare the owner baseline")

      await Instance.dispose()
    },
  })
})


test("automatic research context preserves references for multiple explicit vulnerability classes", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_research_multi_class_" + marker
      const now = Date.now()
      Database.use((db) =>
        db.insert(SessionTable).values({
          id: sessionID,
          project_id: Instance.project.id,
          slug: "research-multi-class",
          directory: dir.path,
          title: "Research multi-class test",
          version: "1",
          time_created: now,
          time_updated: now,
        }).run(),
      )

      const corsTitle = "CORS cross-origin policy reference " + marker
      const disclosureTitle = "Information disclosure reference " + marker
      for (const item of [
        {
          title: corsTitle,
          vulnerabilityClass: "cors",
          sourceURL: "https://research.example.test/" + marker + "/cors",
          signals: ["cors", "cors-policy"],
          lesson: "Compare the observed Access-Control-Allow-Origin behavior with the intended origin policy.",
        },
        {
          title: disclosureTitle,
          vulnerabilityClass: "information-disclosure",
          sourceURL: "https://research.example.test/" + marker + "/disclosure",
          signals: ["information-disclosure"],
          lesson: "Check whether responses expose sensitive data to a caller without the required permission.",
        },
      ]) {
        expect(ReportKnowledge.ingestExternalDetailed({
          title: item.title,
          severity: "unknown",
          vulnerabilityClass: item.vulnerabilityClass,
          sourceURL: item.sourceURL,
          lesson: item.lesson,
          sourceTrust: 85,
          tags: item.signals,
          metadata: {
            source_trust: 85,
            extraction_version: 7,
            extracted: {
              vulnerability_class: item.vulnerabilityClass,
              classification_method: "title-first-dominant-body-v2",
              retrieval_signals: item.signals,
            },
          },
        })).not.toBeNull()
      }

      const context = ResearchContext.generate(
        sessionID,
        "Investigate CORS and information disclosure using the observed response behavior",
      )
      expect(context).toContain(corsTitle)
      expect(context).toContain(disclosureTitle)
      await Instance.dispose()
    },
  })
})
