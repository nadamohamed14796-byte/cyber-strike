import { expect, test } from "bun:test"
import { phaseForWebRecon } from "../../../src/tool/web-recon/phase"

test("read-only recon programs do not require the vulnerability-testing checkpoint", () => {
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

test("technology fingerprinting belongs to live-host discovery", () => {
  expect(phaseForWebRecon("tech_detect")).toBe("live_hosts_ports")
})

test("active vulnerability checks remain explicitly gated", () => {
  for (const program of ["full_recon", "session_scan", "cors_check", "open_redirect"]) {
    expect(phaseForWebRecon(program)).toBe("vulnerability_testing")
  }
})

test("unknown program names fail closed", () => {
  expect(phaseForWebRecon("unrecognized_program")).toBe("vulnerability_testing")
})
