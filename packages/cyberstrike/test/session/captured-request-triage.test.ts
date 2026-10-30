import { describe, expect, test } from "bun:test"
import { isConfirmedEmptyStaticHTML } from "../../src/session/captured-request-triage"

const shell = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blank</title></head><body>\n</body></html>"

function input(overrides: Record<string, unknown> = {}) {
  return {
    method: "GET",
    responseStatus: 200,
    responseContentType: "text/html",
    responseSize: Buffer.byteLength(shell, "utf8"),
    htmlSource: shell,
    rawRequest: "GET /b/blank.htm HTTP/1.1\r\nHost: example.test\r\n\r\n",
    ...overrides,
  }
}

describe("isConfirmedEmptyStaticHTML", () => {
  test("recognizes a complete empty HTML document without dispatching an analyzer", () => {
    expect(isConfirmedEmptyStaticHTML(input())).toBe(true)
  })

  test("does not infer emptiness from the generic HTML response preview", () => {
    expect(isConfirmedEmptyStaticHTML(input({ htmlSource: undefined }))).toBe(false)
  })

  test("rejects truncated or mismatched HTML source", () => {
    expect(isConfirmedEmptyStaticHTML(input({ responseSize: 9999 }))).toBe(false)
  })

  test("keeps documents with scripts, forms, controls, links, or event handlers in analysis", () => {
    for (const html of [
      "<html><body><script>/* app */</script></body></html>",
      "<html><body><form action='/save'></form></body></html>",
      "<html><body><input name='q'></body></html>",
      "<html><head><link rel='stylesheet' href='/app.css'></head><body></body></html>",
      "<html><body onload='boot()'></body></html>",
      "<html><body><iframe src='/frame'></iframe></body></html>",
    ]) {
      expect(isConfirmedEmptyStaticHTML(input({
        htmlSource: html,
        responseSize: Buffer.byteLength(html, "utf8"),
      }))).toBe(false)
    }
  })

  test("does not skip requests with query parameters, bodies, or protocol operations", () => {
    expect(isConfirmedEmptyStaticHTML(input({
      rawRequest: "GET /b/blank.htm?next=1 HTTP/1.1\\r\\nHost: example.test\\r\\n\\r\\n",
    }))).toBe(false)
    expect(isConfirmedEmptyStaticHTML(input({
      rawRequest: "POST /b/blank.htm HTTP/1.1\\r\\nHost: example.test\\r\\n\\r\\nx=1",
      method: "POST",
    }))).toBe(false)
    expect(isConfirmedEmptyStaticHTML(input({ protocol: "graphql", operation: "query:Viewer" }))).toBe(false)
  })

  test("does not skip UI-enriched captures or non-success responses", () => {
    expect(isConfirmedEmptyStaticHTML(input({ triggerElement: "Open blank page" }))).toBe(false)
    expect(isConfirmedEmptyStaticHTML(input({ uiContext: { formName: "profile" } }))).toBe(false)
    expect(isConfirmedEmptyStaticHTML(input({ responseStatus: 403 }))).toBe(false)
  })
})
