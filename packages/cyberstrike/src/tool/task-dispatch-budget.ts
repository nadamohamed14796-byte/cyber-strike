export interface DispatchChild {
  id: string
  title: string
}

export type ProxyDispatchDecision =
  | { allowed: true }
  | { allowed: false; reason: "duplicate"; existingTaskID?: string }
  | { allowed: false; reason: "specialist_budget"; existingSpecialists: string[] }

const REQUEST_MARKER = (requestID: string) => \`[request:\${requestID}]\`
const AGENT_MARKER = (agentID: string) => \`[agent:\${agentID}]\`

/**
 * Runtime guard for automatic Proxy Agent request-scoped delegation.
 * Session titles carry stable request/agent tags so repeat captures reuse the
 * existing evidence without dispatching the same expensive lane again.
 */
export function evaluateProxyRequestDispatch(input: {
  requestID: string
  agentID: string
  children: DispatchChild[]
  reservedAgentIDs?: string[]
  maxSpecialists?: number
}): ProxyDispatchDecision {
  const marker = REQUEST_MARKER(input.requestID)
  const scoped = input.children.filter((child) => child.title.includes(marker))
  const agentMarker = AGENT_MARKER(input.agentID)
  const existing = scoped.find((child) => child.title.includes(agentMarker))
  if (existing) return { allowed: false, reason: "duplicate", existingTaskID: existing.id }

  const isSpecialist = input.agentID.startsWith("proxy-tester-")
  if (!isSpecialist) return { allowed: true }

  const persisted = new Set<string>()
  for (const child of scoped) {
    const match = child.title.match(/\[agent:(proxy-tester-[^\]]+)\]/)
    if (match) persisted.add(match[1])
  }
  for (const agentID of input.reservedAgentIDs ?? []) {
    if (agentID.startsWith("proxy-tester-")) persisted.add(agentID)
  }
  const maxSpecialists = input.maxSpecialists ?? 2
  if (persisted.size >= maxSpecialists) {
    return {
      allowed: false,
      reason: "specialist_budget",
      existingSpecialists: [...persisted].sort(),
    }
  }
  return { allowed: true }
}
