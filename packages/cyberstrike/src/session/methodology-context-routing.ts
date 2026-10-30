/**
 * Methodology is tracking/advisory context only, never an agent-dispatch gate.
 * Keep phase state out of every agent system prompt so delegation decisions do
 * not depend on the current methodology phase or its prerequisites.
 */
export function shouldInjectMethodologyContext(_agentName?: string): boolean {
  return false
}
