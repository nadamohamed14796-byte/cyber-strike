import { expect, test } from "bun:test"
import { phaseForWebRecon } from "../../src/tool/web-recon/phase"

test("technology detection has an advisory live-host phase label", () => {
  expect(phaseForWebRecon("tech_detect")).toBe("live_hosts_ports")
})

test("sitemap, robots, and OpenAPI discovery use the URL-collection label", () => {
  for (const program of ["sitemap_scan", "robots_scan", "openapi_scan"]) {
    expect(phaseForWebRecon(program)).toBe("url_collection")
  }
})

test("active web checks remain classified as vulnerability testing", () => {
  expect(phaseForWebRecon("header_audit")).toBe("vulnerability_testing")
  expect(phaseForWebRecon("sensitive_files")).toBe("vulnerability_testing")
})
