import { expect, test } from "bun:test"
import { executionPhaseForWebRecon } from "../../src/tool/web-recon/phase"

test("ordinary discovery is not blocked by checkpoint phase status", () => {
  for (const program of [
    "tech_detect",
    "sitemap_scan",
    "robots_scan",
    "openapi_scan",
    "header_audit",
    "method_check",
    "graphql_probe",
  ]) {
    expect(executionPhaseForWebRecon(program)).toBe("url_collection")
  }
})

test("active vulnerability-oriented checks remain explicitly gated", () => {
  for (const program of ["sensitive_files", "cors_check", "open_redirect", "full_recon", "session_scan"]) {
    expect(executionPhaseForWebRecon(program)).toBe("vulnerability_testing")
  }
})
