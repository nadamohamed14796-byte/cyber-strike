import { expect, test } from "bun:test"
import { TargetEndpointTool } from "../../src/tool/target-endpoint"

test("target_endpoint accepts method-specific operations and source-specific evidence", async () => {
  const tool = await TargetEndpointTool.init()
  const parsed = tool.parameters.parse({
    target_url: "https://example.com",
    origin: "https://api.example.com",
    path: "/api/users/{id}",
    source_files: ["assets/users.js"],
    operations: [
      {
        method: "POST",
        method_evidence_sources: ["javascript"],
        body_parameters: ["name", "email"],
        header_names: ["content-type", "authorization"],
        content_types: ["application/json"],
        evidence: [{
          source: "javascript",
          body_parameters: ["name", "email"],
          header_names: ["content-type", "authorization"],
          content_types: ["application/json"],
          source_files: ["assets/users.js"],
          confidence: "candidate",
        }],
      },
      {
        method: "GET",
        method_evidence_sources: ["traffic"],
        query_parameters: ["include"],
        request_ids: ["req-get-1"],
        observed_in_traffic: true,
        confidence: "observed",
        evidence: [{
          source: "traffic",
          query_parameters: ["include"],
          request_ids: ["req-get-1"],
          confidence: "observed",
        }],
      },
    ],
    unattributed: {
      query_parameters: ["route-level-clue"],
      source_files: ["assets/routes.js"],
    },
  })

  expect(parsed.operations).toHaveLength(2)
  expect(parsed.operations[0]?.method).toBe("POST")
  expect(parsed.operations[0]?.content_types).toEqual(["application/json"])
  expect(parsed.operations[0]?.evidence?.[0]?.source).toBe("javascript")
  expect(parsed.operations[1]?.method).toBe("GET")
  expect(parsed.operations[1]?.request_ids).toEqual(["req-get-1"])
  expect(parsed.operations[1]?.method_evidence_sources).toEqual(["traffic"])
  expect(parsed.unattributed?.query_parameters).toEqual(["route-level-clue"])
})

test("target_endpoint rejects missing operations and non-absolute paths", async () => {
  const tool = await TargetEndpointTool.init()
  const base = {
    target_url: "https://example.com",
    origin: "https://api.example.com",
  }
  expect(tool.parameters.safeParse({
    ...base,
    path: "/api/users",
    operations: [],
  }).success).toBe(false)
  expect(tool.parameters.safeParse({
    ...base,
    path: "api/users",
    operations: [{ method: "GET" }],
  }).success).toBe(false)
})

test("target_endpoint accepts valid HTTP method tokens and rejects whitespace", async () => {
  const tool = await TargetEndpointTool.init()
  const parsed = tool.parameters.parse({
    target_url: "https://example.com",
    origin: "https://api.example.com",
    path: "/api/users",
    operations: [{ method: "GET" }],
  })
  expect(parsed.operations[0]?.method).toBe("GET")
  expect(tool.parameters.safeParse({
    target_url: "https://example.com",
    origin: "https://api.example.com",
    path: "/api/users",
    operations: [{ method: "BAD METHOD" }],
  }).success).toBe(false)
})
