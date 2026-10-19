import { expect, test } from "bun:test"
import { requiredPhasesForWebRecon } from "../../src/tool/web-recon/phase"

test("technology detection can run in live-host or active URL-collection phase", () => {
  expect(requiredPhasesForWebRecon("tech_detect")).toEqual(["live_hosts_ports", "url_collection"])
})

test("sitemap, robots, and OpenAPI discovery are gated by URL collection", () => {
  for (const program of ["sitemap_scan", "robots_scan", "openapi_scan"]) {
    expect(requiredPhasesForWebRecon(program)).toEqual(["url_collection"])
  }
})

test("active web checks remain gated by vulnerability testing", () => {
  expect(requiredPhasesForWebRecon("header_audit")).toEqual(["vulnerability_testing"])
  expect(requiredPhasesForWebRecon("sensitive_files")).toEqual(["vulnerability_testing"])
})
