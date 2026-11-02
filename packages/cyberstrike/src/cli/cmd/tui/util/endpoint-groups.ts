import { formatEndpointHost } from "./format"

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

/**
 * Build the sidebar's domain → endpoint → HTTP operation → captured request tree.
 * Request rows are never merged: every capture remains independently addressable.
 */
export function groupCapturedRequests<T extends CapturedEndpointRequest>(requests: T[]): CapturedDomainGroup<T>[] {
  const domains = new Map<string, Map<string, Map<string, T[]>>>()

  for (const request of requests) {
    const host = formatEndpointHost(request.host, request.port) || "(unknown host)"
    const domainKey = request.origin || host
    let endpoints = domains.get(domainKey)
    if (!endpoints) {
      endpoints = new Map()
      domains.set(domainKey, endpoints)
    }

    let operations = endpoints.get(request.normalized_path)
    if (!operations) {
      operations = new Map()
      endpoints.set(request.normalized_path, operations)
    }

    const operationKey = [request.method.toUpperCase(), request.protocol ?? "", request.operation ?? ""].join("|")
    const captures = operations.get(operationKey)
    if (captures) captures.push(request)
    else operations.set(operationKey, [request])
  }

  return [...domains.entries()]
    .map(([key, endpoints]) => {
      const label = formatEndpointHost(
        requests.find((request) => (request.origin || formatEndpointHost(request.host, request.port) || "(unknown host)") === key)?.host,
        requests.find((request) => (request.origin || formatEndpointHost(request.host, request.port) || "(unknown host)") === key)?.port,
      ) || key
      const endpointGroups = [...endpoints.entries()]
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
        label,
        endpoints: endpointGroups,
        requestCount: endpointGroups.reduce((sum, endpoint) => sum + endpoint.requestCount, 0),
      }
    })
    .sort((a, b) => a.label.localeCompare(b.label) || a.key.localeCompare(b.key))
}
