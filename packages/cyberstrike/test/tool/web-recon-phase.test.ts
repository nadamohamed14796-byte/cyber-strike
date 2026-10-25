import { expect, test } from "bun:test"
import { executionPhaseForWebRecon } from "../../src/tool/web-recon/phase"

test("read-only discovery programs are not gated by checkpoint status", () => {
  for (const program of [
    "sitemap_scan",
    "robots_scan",
    "openapi_scan",
    "header_audit",
    "method_check",
    "graphql_probe",
    "tech_detect",
  ]) {
    expect(executionPhaseForWebRecon(program)).toBe("url_collection")
  }
})

test("sensitive-file collection is ordinary read-only recon", () => {
  expect(executionPhaseForWebRecon("sensitive_files")).toBe("url_collection")
})

test("active vulnerability-oriented web-recon programs remain opt-in", () => {
  for (const program of [
    "cors_check",
    "open_redirect",
    "full_recon",
    "session_scan",
  ]) {
    expect(executionPhaseForWebRecon(program)).toBe("vulnerability_testing")
  }
})
