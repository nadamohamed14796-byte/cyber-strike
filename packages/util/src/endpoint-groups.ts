/** Shared grouping model for captured HTTP requests across the TUI and Web UI. */
export type CapturedEndpointRequest = {
  id: string
  host?: string
  port?: number
  origin?: string
  normalized_path: string
  method: string
  protocol?: string
  operation?: string
}

export type CapturedOperationGroup<T extends CapturedEndpointRequest> = {
  key: string
  method: string
  protocol?: string
  operation?: string
  requests: T[]
}

export type CapturedEndpointGroup<T extends CapturedEndpointRequest> = {
  path: string
  operations: CapturedOperationGroup<T>[]
  requestCount: number
}

export type CapturedDomainGroup<T extends CapturedEndpointRequest> = {
  key: string
  label: string
  endpoints: CapturedEndpointGroup<T>[]
  requestCount: number
}

function endpointHost(host: string | undefined, port: number | undefined): string {
  if (!host) return ""
  if (port == null || port === 80 || port === 443) return host
  return `${host}:${port}`
}

/** Build domain → endpoint → HTTP operation → independent captured-request groups. */
export function groupCapturedRequests<T extends CapturedEndpointRequest>(requests: T[]): CapturedDomainGroup<T>[] {
  const domains = new Map<string, { label: string; endpoints: Map<string, Map<string, T[]>> }>()

  for (const request of requests) {
    let host = endpointHost(request.host, request.port)
    if (!host && request.origin) {
      try {
        const origin = new URL(request.origin)
        host = endpointHost(origin.hostname, origin.port ? Number(origin.port) : undefined)
      } catch {
        // Preserve malformed/legacy origin rows in the unknown-host bucket.
      }
    }
    host = host || "(unknown host)"
    const domainKey = host.toLowerCase()
    let domain = domains.get(domainKey)
    if (!domain) {
      domain = { label: host, endpoints: new Map() }
      domains.set(domainKey, domain)
    }

    let operations = domain.endpoints.get(request.normalized_path)
    if (!operations) {
      operations = new Map()
      domain.endpoints.set(request.normalized_path, operations)
    }

    const operationKey = [request.method.toUpperCase(), request.protocol ?? "", request.operation ?? ""].join("|")
    const captures = operations.get(operationKey)
    if (captures) captures.push(request)
    else operations.set(operationKey, [request])
  }

  return [...domains.entries()]
    .map(([key, domain]) => {
      const endpoints = [...domain.endpoints.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([path, operations]) => {
          const operationGroups = [...operations.entries()]
            .map(([operationKey, captures]) => {
              const first = captures[0]!
              return {
                key: operationKey,
                method: first.method.toUpperCase(),
                protocol: first.protocol,
                operation: first.operation,
                requests: captures.toSorted((a, b) => a.id.localeCompare(b.id)),
              }
            })
            .sort((a, b) =>
              a.method.localeCompare(b.method) ||
              (a.protocol ?? "").localeCompare(b.protocol ?? "") ||
              (a.operation ?? "").localeCompare(b.operation ?? ""),
            )
          return {
            path,
            operations: operationGroups,
            requestCount: operationGroups.reduce((sum, operation) => sum + operation.requests.length, 0),
          }
        })
      return {
        key,
        label: domain.label,
        endpoints,
        requestCount: endpoints.reduce((sum, endpoint) => sum + endpoint.requestCount, 0),
      }
    })
    .sort((a, b) => a.label.localeCompare(b.label) || a.key.localeCompare(b.key))
}
