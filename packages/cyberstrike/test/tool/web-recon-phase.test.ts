import { expect, test } from "bun:test"
import { executionPhaseForWebRecon } from "../../src/tool/web-recon/phase"

test("passive inventory programs remain available during ordinary reconnaissance", () => {
  for (const program of [
    "sitemap_scan",
    "robots_scan",
    "openapi_scan",
    "header_audit",
    "tech_detect",
  ]) {
    expect(executionPhaseForWebRecon(program)).toBe("url_collection")
  }
})

test("sensitive-file, GraphQL, method, and vulnerability probes require opt-in testing", () => {
  for (const program of [
    "sensitive_files",
    "graphql_probe",
    "method_check",
    "cors_check",
    "open_redirect",
    "full_recon",
    "session_scan",
  ]) {
    expect(executionPhaseForWebRecon(program)).toBe("vulnerability_testing")
  }
})
