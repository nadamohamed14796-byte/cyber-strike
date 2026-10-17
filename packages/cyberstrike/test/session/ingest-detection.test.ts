import { expect, test } from "bun:test"
import { looksLikeHTTPRequest } from "../../src/session/ingest-detection"

test("recognizes a complete captured HTTP request", () => {
  expect(looksLikeHTTPRequest("GET /api/users HTTP/1.1\r\nHost: app.example.test\r\n\r\n")).toBe(true)
})

test("recognizes a truncated HTTP request with recognizable headers", () => {
  expect(looksLikeHTTPRequest("POST /api/users\nHost: app.example.test\nContent-Type: application/json")).toBe(true)
})

test("recognizes a truncated request line even when headers were lost", () => {
  expect(looksLikeHTTPRequest("GET /api/users")).toBe(true)
  expect(looksLikeHTTPRequest("GET https://app.example.test/api/users")).toBe(true)
})

test("treats explicit HTTP capture metadata as HTTP even if the raw request is malformed", () => {
  expect(looksLikeHTTPRequest("not a request", true)).toBe(true)
})

test("does not classify ordinary chat text as HTTP", () => {
  expect(looksLikeHTTPRequest("Can you explain how this API works?")).toBe(false)
  expect(looksLikeHTTPRequest("I sent a GET request yesterday.")).toBe(false)
})
