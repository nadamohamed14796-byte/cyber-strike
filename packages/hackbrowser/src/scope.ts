// ============================================================
// Network scope (ARCHITECTURE.md §1.2 — Network Scope)
//
// Scope = which hostnames the agent navigates and forwards to CyberStrike.
// Distinct from --exclude (semantic task filter, planner-side).
//
// Explicit scope patterns follow least-privilege matching:
//   - bare host: exact host only
//   - *.example.com: example.com itself and all subdomains on label boundaries
// When no scope is supplied, default to the exact starting hostname. A target URL
// does not imply authorization for sibling subdomains or the whole registrable domain.
// ============================================================

export type ScopeMatcher = (host: string) => boolean

/**
 * Strip protocol, path, query, port, trailing dots; lowercase.
 * Accepts "https://app.test.com:8080/foo?x=1" or bare "app.test.com".
 * Wildcard prefix "*." is preserved.
 */
export function normalizeScope(input: string): string {
  let s = input.trim().toLowerCase()
  if (!s) return ""
  s = s.replace(/^https?:\/\//, "")
  s = s.split(/[/?#]/)[0] ?? ""
  s = s.replace(/:\d+$/, "")
  while (s.endsWith(".")) s = s.slice(0, -1)
  return s
}

/**
 * Derive the least-privileged default scope from the starting URL.
 * Never infer sibling-subdomain authorization from a single target URL.
 */
export function deriveScope(targetUrl: string): string {
  return new URL(targetUrl).hostname.toLowerCase().replace(/\.+$/, "")
}

/**
 * Build a matcher from one or more scope patterns (OR semantics).
 * A bare host matches exactly; an explicit wildcard includes its apex and subdomains.
 * Empty input rejects every host.
 */
export function makeMatcher(scopes: readonly string[]): ScopeMatcher {
  const patterns = scopes
    .map(normalizeScope)
    .filter((scope) => scope.length > 0)
    .map((scope) => ({ host: scope.startsWith("*.") ? scope.slice(2) : scope, wildcard: scope.startsWith("*.") }))
  if (patterns.length === 0) return () => false
  return (host: string) => {
    const normalizedHost = host.toLowerCase().replace(/\.+$/, "")
    return patterns.some(({ host: base, wildcard }) =>
      wildcard ? normalizedHost === base || normalizedHost.endsWith("." + base) : normalizedHost === base,
    )
  }
}
