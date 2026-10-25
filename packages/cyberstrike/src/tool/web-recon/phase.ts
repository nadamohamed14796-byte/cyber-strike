import type { ReconPhase } from "../../target/recon-gate"

/** Keep read-only discovery in recon; require the explicit gate for active or unknown checks. */
const READ_ONLY_RECON_PROGRAMS = new Set([
  "sitemap_scan",
  "robots_scan",
  "openapi_scan",
  "graphql_probe",
  "header_audit",
  "sensitive_files",
  "method_check",
])

export function phaseForWebRecon(program: string): ReconPhase {
  if (program === "tech_detect") return "live_hosts_ports"
  if (READ_ONLY_RECON_PROGRAMS.has(program)) return "url_collection"
  // Active checks and unknown program names fail closed.
  return "vulnerability_testing"
}
