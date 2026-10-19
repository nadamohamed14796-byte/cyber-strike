import type { ReconPhase } from "../../target/recon-gate"

/**
 * Return ordered checkpoint phases for a standalone web-recon program.
 * tech_detect normally belongs to live-host inventory, but can also run as
 * passive enrichment during an already-active URL collection phase.
 */
export function requiredPhasesForWebRecon(program: string): ReconPhase[] {
  if (["sitemap_scan", "robots_scan", "openapi_scan"].includes(program)) return ["url_collection"]
  if (program === "tech_detect") return ["live_hosts_ports", "url_collection"]
  return ["vulnerability_testing"]
}
