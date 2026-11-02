export interface DispatchChild {
  id: string
  title: string
}

export type ProxyDispatchDecision =
  | { allowed: true }
  | { allowed: false; reason: "duplicate"; existingTaskID?: string }

const REQUEST_MARKER = (requestID: string) => "[request:" + requestID + "]"
const AGENT_MARKER = (agentID: string) => "[agent:" + agentID + "]"

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
}): ProxyDispatchDecision {
  const marker = REQUEST_MARKER(input.requestID)
  const scoped = input.children.filter((child) => child.title.includes(marker))
  const agentMarker = AGENT_MARKER(input.agentID)
  const existing = scoped.find((child) => child.title.includes(agentMarker))
  if (existing) return { allowed: false, reason: "duplicate", existingTaskID: existing.id }
  if ((input.reservedAgentIDs ?? []).includes(input.agentID)) {
    return { allowed: false, reason: "duplicate" }
  }

  // Distinct evidence-supported lanes are not subject to a total-count budget.
  // Concurrency is bounded separately by AgentTaskConcurrency; this guard only
  // prevents the same lane from being dispatched twice for one request.
  return { allowed: true }
}
