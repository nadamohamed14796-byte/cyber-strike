import type { ReconPhase } from "../../target/recon-gate"

/**
 * Classify a web-recon request by impact. Ordinary discovery is not assigned
 * to a checkpoint-specific tool allowlist; only vulnerability-oriented probes
 * require the explicit testing handoff.
 */
export function executionPhaseForWebRecon(program: string): ReconPhase {
  if ([
    "sensitive_files",
    "cors_check",
    "open_redirect",
    "full_recon",
    "session_scan",
  ].includes(program)) return "vulnerability_testing"

  // These programs are read-only discovery or configuration inventory.
  // The returned ordinary phase is descriptive only; runtime scope checks decide
  // which URLs can be requested, regardless of checkpoint status.
  return "url_collection"
}
