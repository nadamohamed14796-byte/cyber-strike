import { expect, test } from "bun:test"
import { phaseForWebRecon } from "../../src/tool/web-recon/phase"

test("technology detection has an advisory live-host phase label", () => {
  expect(phaseForWebRecon("tech_detect")).toBe("live_hosts_ports")
})

test("read-only discovery uses the URL-collection label", () => {
  for (const program of [
    "sitemap_scan",
    "robots_scan",
    "openapi_scan",
    "graphql_probe",
    "header_audit",
    "sensitive_files",
    "method_check",
  ]) {
    expect(phaseForWebRecon(program)).toBe("url_collection")
  }
})

test("active web checks remain classified as vulnerability testing", () => {
  for (const program of ["full_recon", "session_scan", "cors_check", "open_redirect"]) {
    expect(phaseForWebRecon(program)).toBe("vulnerability_testing")
  }
})
