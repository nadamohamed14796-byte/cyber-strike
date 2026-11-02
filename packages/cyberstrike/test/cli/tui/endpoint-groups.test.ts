import { describe, expect, test } from "bun:test"
import { groupCapturedRequests } from "../../../src/cli/cmd/tui/util/endpoint-groups"

const request = (input: Partial<{
  id: string
  host: string
  port: number
  origin: string
  normalized_path: string
  method: string
  protocol: string
  operation: string
}> = {}) => ({
  id: input.id ?? "req_1",
  host: input.host ?? "app.example.com",
  port: input.port,
  origin: input.origin ?? "https://app.example.com",
  normalized_path: input.normalized_path ?? "/api/users",
  method: input.method ?? "GET",
  protocol: input.protocol,
  operation: input.operation,
})

describe("TUI captured request grouping", () => {
  test("groups requests by domain, then endpoint, then HTTP method", () => {
    const groups = groupCapturedRequests([
      request({ id: "req_3", normalized_path: "/api/users", method: "POST" }),
      request({ id: "req_2", normalized_path: "/api/profile", method: "GET" }),
      request({ id: "req_1", normalized_path: "/api/users", method: "GET" }),
      request({ id: "req_4", host: "api.example.net", origin: "https://api.example.net", normalized_path: "/v1/items" }),
    ])

    expect(groups).toHaveLength(2)
    const app = groups.find((group) => group.label === "app.example.com")!
    expect(app.requestCount).toBe(3)
    expect(app.endpoints.map((endpoint) => endpoint.path)).toEqual(["/api/profile", "/api/users"])
    const users = app.endpoints.find((endpoint) => endpoint.path === "/api/users")!
    expect(users.operations.map((operation) => operation.method)).toEqual(["GET", "POST"])
    expect(users.operations[0]!.requests.map((capture) => capture.id)).toEqual(["req_1"])
    expect(groups.find((group) => group.label === "api.example.net")?.endpoints[0]?.path).toBe("/v1/items")
  })

  test("keeps different origins separate even when host labels match", () => {
    const groups = groupCapturedRequests([
      request({ id: "http", origin: "http://app.example.com" }),
      request({ id: "https", origin: "https://app.example.com" }),
    ])
    expect(groups).toHaveLength(2)
    expect(groups.map((group) => group.requestCount)).toEqual([1, 1])
  })

  test("preserves independent captures for the same operation and separates GraphQL operations", () => {
    const groups = groupCapturedRequests([
      request({ id: "req_2", protocol: "graphql", operation: "query:Viewer" }),
      request({ id: "req_1", protocol: "graphql", operation: "query:Viewer" }),
      request({ id: "req_3", protocol: "graphql", operation: "mutation:UpdateViewer" }),
    ])
    const operations = groups[0]!.endpoints[0]!.operations
    expect(operations).toHaveLength(2)
    expect(operations[0]!.requests.map((capture) => capture.id)).toEqual(["req_1", "req_2"])
    expect(operations[1]!.operation).toBe("mutation:UpdateViewer")
  })

  test("keeps unknown hosts grouped instead of dropping requests", () => {
    const groups = groupCapturedRequests([request({ host: undefined, origin: undefined })])
    expect(groups[0]?.label).toBe("(unknown host)")
    expect(groups[0]?.requestCount).toBe(1)
  })
})
