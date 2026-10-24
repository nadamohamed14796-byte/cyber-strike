import type { ReconPhase } from "../../target/recon-gate"

/**
 * Classify standalone web-recon programs by impact, not by an exhaustive tool
 * allowlist. Passive/read-only discovery is available at any ordinary recon
 * checkpoint after the caller's persisted request-level scope check. Checks
 * that test vulnerability hypotheses remain behind the explicit opt-in gate.
 */
export function requiredPhasesForWebRecon(program: string): ReconPhase[] {
  if (program === "tech_detect") return ["live_hosts_ports", "url_collection"]
  if ([
    "sitemap_scan",
    "robots_scan",
    "openapi_scan",
    "header_audit",
    "method_check",
    "graphql_probe",
  ].includes(program)) return ["url_collection"]

  // These programs issue active vulnerability-oriented probes or combine
  // passive discovery with active tests; do not launch them from recon-only runs.
  return ["vulnerability_testing"]
}
