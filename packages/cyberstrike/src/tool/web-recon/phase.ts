import type { ReconPhase } from "../../target/recon-gate"

/** Classify web-recon programs only to distinguish passive recon from active testing. */
export function phaseForWebRecon(program: string): ReconPhase {
  if (["sitemap_scan", "robots_scan", "openapi_scan"].includes(program)) return "url_collection"
  if (program === "tech_detect") return "live_hosts_ports"
  return "vulnerability_testing"
}
