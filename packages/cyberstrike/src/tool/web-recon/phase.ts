import type { ReconPhase } from "../../target/recon-gate"

/**
 * Classify programs by their actual behavior, not by a fixed phase-to-tool allowlist.
 * Read-only discovery/audit programs can run during ordinary recon. Active vulnerability
 * checks stay behind the explicit vulnerability-testing checkpoint. Unknown programs fail closed.
 */
const READ_ONLY_RECON_PROGRAMS = new Set([
  "sitemap_scan",
  "robots_scan",
  "openapi_scan",
  "graphql_probe",
  "header_audit",
  "sensitive_files",
  "method_check",
])

const ACTIVE_TEST_PROGRAMS = new Set([
  "full_recon",
  "session_scan",
  "cors_check",
  "open_redirect",
])

export function phaseForWebRecon(program: string): ReconPhase {
  if (program === "tech_detect") return "live_hosts_ports"
  if (READ_ONLY_RECON_PROGRAMS.has(program)) return "url_collection"
  // Explicitly known active programs and unknown names both fail closed.
  if (ACTIVE_TEST_PROGRAMS.has(program)) return "vulnerability_testing"
  return "vulnerability_testing"
}
