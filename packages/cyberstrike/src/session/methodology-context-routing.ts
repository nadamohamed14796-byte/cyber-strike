/**
 * Proxy request analysis is an independent intake lane, not a Recon phase.
 * Keep methodology prompt injection disabled for the Proxy Agent so captured
 * requests remain analyzable before, during, or after the Recon workflow.
 */
export function shouldInjectMethodologyContext(agentName?: string): boolean {
  return agentName !== "proxy-agent"
}
