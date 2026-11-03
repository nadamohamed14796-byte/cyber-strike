import type { ReconPhase } from "../../target/recon-gate"

/**
 * Classify a web-recon request by impact. Passive inventory stays available
 * during normal recon; probes that can disclose sensitive resources, exercise
 * API behavior, or test browser/server security boundaries require the explicit
 * vulnerability-testing handoff.
 */
export function executionPhaseForWebRecon(program: string): ReconPhase {
  if ([
    "sensitive_files",
    "graphql_probe",
    "method_check",
    "cors_check",
    "open_redirect",
    "full_recon",
    "session_scan",
  ].includes(program)) return "vulnerability_testing"

  return "url_collection"
}
