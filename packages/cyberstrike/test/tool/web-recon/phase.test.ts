import { expect, test } from "bun:test"
import { requiredPhasesForWebRecon } from "../../../src/tool/web-recon/phase"

test("read-only discovery programs are available during ordinary recon", () => {
  for (const program of [
    "sitemap_scan",
    "robots_scan",
    "openapi_scan",
    "header_audit",
    "method_check",
    "graphql_probe",
  ]) {
    expect(requiredPhasesForWebRecon(program)).toEqual(["url_collection"])
  }
  expect(requiredPhasesForWebRecon("tech_detect")).toEqual(["live_hosts_ports", "url_collection"])
})

test("active vulnerability-oriented web-recon programs remain opt-in", () => {
  for (const program of [
    "sensitive_files",
    "cors_check",
    "open_redirect",
    "full_recon",
    "session_scan",
  ]) {
    expect(requiredPhasesForWebRecon(program)).toEqual(["vulnerability_testing"])
  }
})
