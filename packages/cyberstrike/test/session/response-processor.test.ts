import { expect, test } from "bun:test"
import { processResponse } from "../../src/session/response-processor"

test("keeps full JavaScript source while preserving the existing bounded prompt preview", () => {
  const source = 'fetch("/api/full-source");\n' + "x".repeat(110 * 1024)
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "application/javascript; charset=utf-8" },
    body: source,
  })

  expect(processed.originalSize).toBe(Buffer.byteLength(source, "utf-8"))
  expect(processed.content).toContain("[TRUNCATED - showing first 100KB")
  expect(processed.content.length).toBeLessThan(source.length)
  expect(processed.javascriptSource).toBe(source)
})

test("does not duplicate full-source storage for ordinary JSON responses", () => {
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ok: true }),
  })

  expect(processed.content).toContain('"ok":true')
  expect(processed.javascriptSource).toBeUndefined()
})


test("recognizes JavaScript assets by URL when the response MIME type is wrong", () => {
  const source = 'fetch("/api/mislabelled-source")'
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "text/plain" },
    url: "https://app.example.test/assets/main.js?cache=1",
    body: source,
  })
  expect(processed.javascriptSource).toBe(source)
})


test("keeps captured source-map bodies available to static analysis even when JSON is truncated for the LLM preview", () => {
  const map = JSON.stringify({
    version: 3,
    sources: ["src/profile.ts"],
    sourcesContent: ['fetch("/api/profile");'],
    names: [],
    mappings: "",
  }) + " ".repeat(110 * 1024)
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "application/json" },
    url: "https://app.example.test/assets/app.js.map?version=2",
    body: map,
  })

  expect(processed.content).toContain("[TRUNCATED - showing first 100KB")
  expect(processed.content.length).toBeLessThan(map.length)
  expect(processed.javascriptSource).toBe(map)
})

test("recognizes source-map MIME types when the URL has no .map suffix", () => {
  const body = JSON.stringify({ version: 3, sources: [], sourcesContent: [], names: [], mappings: "" })
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "application/source-map+json" },
    url: "https://app.example.test/assets/generated",
    body,
  })
  expect(processed.javascriptSource).toBe(body)
})

 
test("extracts executable inline HTML scripts for independent static analysis", () => {
  const html = [
    '<script>fetch("/api/inline-one")</script>',
    '<script type="module">fetch("/api/inline-two")</script>',
    '<script type="application/ld+json">{"name":"not executable"}</script>',
    '<script type="importmap">{"imports":{"react":"/react.js"}}</script>',
  ].join("")
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    url: "https://app.example.test/account",
    body: html,
  })

  expect(processed.inlineJavaScriptSources).toHaveLength(2)
  expect(processed.inlineJavaScriptSources?.[0]).toContain("/api/inline-one")
  expect(processed.inlineJavaScriptSources?.[1]).toContain("/api/inline-two")
  expect(JSON.stringify(processed.inlineJavaScriptSources)).not.toContain("not executable")
})

test("extracts inline scripts from XHTML responses as well", () => {
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "application/xhtml+xml" },
    url: "https://app.example.test/page.xhtml",
    body: '<html><script>fetch("/api/xhtml")</script></html>',
  })
  expect(processed.inlineJavaScriptSources).toEqual(['fetch("/api/xhtml")'])
  expect(processed.htmlSource).toContain("/api/xhtml")
})
