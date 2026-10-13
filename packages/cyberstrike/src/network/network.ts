import { readFileSync } from "node:fs"
import { Config } from "../config/config"

/**
 * Destination-specific proxy/TLS policy for authorized target traffic.
 * Callers resolve policy for every URL instead of independently interpreting config.
 * We deliberately do not install a global fetch hook or proxy LLM/OAuth calls.
 */
export namespace Network {
  export interface Outbound {
    proxy?: string
    ca?: string
    rejectUnauthorized?: boolean
    clientCertificate?: { cert?: string; key?: string; passphrase?: string }
  }

  export interface BrowserOptions {
    proxy?: { server: string; username?: string; password?: string; bypass?: string }
    ignoreHTTPSErrors?: boolean
  }

  const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"])

  export function normalizeHost(value: string): string {
    let host = value.trim().toLowerCase().replace(/\.+$/, "")
    if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1)
    if (!/^[\x00-\x7f]*$/.test(host)) {
      try { host = new URL("http://" + host).hostname } catch { /* safe mismatch below */ }
    }
    return host
  }

  export function matchHost(pattern: string, host: string): boolean {
    const candidate = normalizeHost(host)
    const rule = pattern.trim().toLowerCase()
    if (!rule || (rule.includes("*") && !rule.startsWith("*."))) return false
    const base = normalizeHost(rule.startsWith("*.") ? rule.slice(2) : rule)
    return candidate === base || candidate.endsWith("." + base)
  }

  export function isLoopback(host: string): boolean {
    const normalized = normalizeHost(host)
    return LOOPBACK.has(normalized) || normalized.endsWith(".localhost") || /^127\./.test(normalized)
  }

  export function isBypassed(host: string, bypass: readonly string[] = [], includeLoopback = false): boolean {
    if (!includeLoopback && isLoopback(host)) return true
    return bypass.some((pattern) => matchHost(pattern, host))
  }

  function parseProxy(value: string, username?: string, password?: string): { url: string; username?: string; password?: string } {
    let url: URL
    try { url = new URL(value) } catch { throw new Error("network.proxy.url must be a valid HTTP(S) proxy URL.") }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("network.proxy.url must use HTTP(S) (http:// or https://). SOCKS proxies are not supported for replay requests.")
    }
    if (!url.hostname || (url.pathname !== "/" && url.pathname !== "")) {
      throw new Error("network.proxy.url must be a proxy origin without a path.")
    }
    if (url.username || url.password) {
      throw new Error("Do not embed proxy credentials in network.proxy.url; use network.proxy.auth.")
    }
    return {
      url: url.origin,
      ...(username ? { username } : {}),
      ...(password ? { password } : {}),
    }
  }

  export function toProxyUrl(value: string, username?: string, password?: string): string {
    const parsed = parseProxy(value, username, password)
    if (!parsed.username && !parsed.password) return parsed.url
    const result = new URL(parsed.url)
    // URL setters encode spaces and reserved characters, but leave literal percent signs
    // untouched. Encode those first so a credential containing '%' round-trips exactly once.
    if (parsed.username) result.username = parsed.username.replace(/%/g, "%25")
    if (parsed.password) result.password = parsed.password.replace(/%/g, "%25")
    return result.toString()
  }

  function readCertificate(path: string | undefined, label: string): string | undefined {
    if (!path) return undefined
    try {
      return readFileSync(path, "utf8")
    } catch (error) {
      throw new Error(`Cannot read ${label} file at ${path}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  function certificateHostAndPort(input: string): { host: string; port?: number } {
    const value = input.trim()
    if (value.startsWith("[")) {
      const end = value.indexOf("]")
      if (end >= 0) {
        const suffix = value.slice(end + 1)
        if (/^:\d+$/.test(suffix)) return { host: value.slice(1, end), port: Number(suffix.slice(1)) }
        return { host: value.slice(1, end) }
      }
    }
    const colon = value.lastIndexOf(":")
    if (colon > 0 && /^\d+$/.test(value.slice(colon + 1)) && value.slice(0, colon).indexOf(":") < 0) {
      return { host: value.slice(0, colon), port: Number(value.slice(colon + 1)) }
    }
    return { host: value }
  }

  function certificateFor(host: string, port: number, config: Config.Tls | undefined) {
    for (const certificate of config?.clientCertificates ?? []) {
      const parsed = certificateHostAndPort(certificate.host)
      if (parsed.port !== undefined && parsed.port !== port) continue
      if (!matchHost(parsed.host, host)) continue
      if (certificate.pfxPath && (!certificate.certPath || !certificate.keyPath)) {
        throw new Error("PFX/PKCS#12 client certificates are not supported by replay; provide PEM certPath and keyPath.")
      }
      if (!certificate.certPath || !certificate.keyPath) {
        throw new Error(`Client certificate for ${certificate.host} requires both certPath and keyPath.`)
      }
      return {
        cert: readCertificate(certificate.certPath, "client certificate"),
        key: readCertificate(certificate.keyPath, "client private key"),
        passphrase: certificate.passphrase,
      }
    }
    return undefined
  }

  export async function forUrl(value: string): Promise<Outbound> {
    let url: URL
    try { url = new URL(value) } catch { throw new Error("Target URL must be absolute and valid before resolving proxy/TLS policy.") }
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Target URL must use HTTP or HTTPS.")
    if (url.username || url.password) throw new Error("Target URL must not contain embedded credentials.")
    const config = (await Config.get()).network
    const output: Outbound = {}
    const proxy = config?.proxy
    if (proxy?.url && proxy.enabled !== false && !isBypassed(url.hostname, proxy.bypass ?? [], proxy.includeLoopback === true)) {
      const resolved = parseProxy(proxy.url, proxy.auth?.username, proxy.auth?.password)
      output.proxy = toProxyUrl(resolved.url, resolved.username, resolved.password)
    }
    const tls = config?.tls
    if (tls?.caPath) output.ca = readCertificate(tls.caPath, "TLS CA certificate")
    if (tls?.rejectUnauthorized !== undefined) output.rejectUnauthorized = tls.rejectUnauthorized
    const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80
    output.clientCertificate = certificateFor(url.hostname, port, tls)
    return output
  }

  /** Secure by default. insecure_tls=true is the only implicit per-call override. */
  export function rejectUnauthorized(insecureTls: boolean | undefined, outbound: Outbound): boolean {
    if (insecureTls !== undefined) return !insecureTls
    return outbound.rejectUnauthorized ?? true
  }

  /** Shared fetch transport mapping for proxy, trust roots, and client certificates. */
  export function toFetchInit(outbound: Outbound): { proxy?: string; tls?: Record<string, unknown> } {
    const init: { proxy?: string; tls?: Record<string, unknown> } = {}
    if (outbound.proxy) init.proxy = outbound.proxy
    const tls: Record<string, unknown> = { rejectUnauthorized: outbound.rejectUnauthorized ?? true }
    if (outbound.ca) tls.ca = outbound.ca
    if (outbound.clientCertificate?.cert) tls.cert = outbound.clientCertificate.cert
    if (outbound.clientCertificate?.key) tls.key = outbound.clientCertificate.key
    if (outbound.clientCertificate?.passphrase) tls.passphrase = outbound.clientCertificate.passphrase
    init.tls = tls
    return init
  }

  export function chromiumBypass(patterns: readonly string[], includeLoopback: boolean): string[] {
    // Chromium implicitly bypasses loopback even when the configured bypass list is empty.
    // The special < -loopback > rule (without spaces) disables that implicit rule, allowing
    // an explicitly configured local proxy to receive loopback traffic too.
    const result = includeLoopback ? ["<-loopback>"] : ["localhost", ".localhost", "127.0.0.1", "::1"]
    for (const value of patterns) {
      const pattern = value.trim()
      if (!pattern) continue
      result.push(pattern.startsWith("*.") ? "." + pattern.slice(2) : pattern)
    }
    return [...new Set(result)]
  }

  export async function forBrowser(): Promise<BrowserOptions> {
    const config = (await Config.get()).network
    const output: BrowserOptions = {}
    const proxy = config?.proxy
    if (proxy?.url && proxy.enabled !== false) {
      const parsed = parseProxy(proxy.url, proxy.auth?.username, proxy.auth?.password)
      output.proxy = {
        server: parsed.url,
        ...(parsed.username ? { username: parsed.username } : {}),
        ...(parsed.password ? { password: parsed.password } : {}),
        bypass: chromiumBypass(proxy.bypass ?? [], proxy.includeLoopback === true).join(","),
      }
    }
    const tls = config?.tls
    if (tls?.clientCertificates?.length) {
      throw new Error("The browser crawler cannot use configured mutual-TLS client certificates. Use HTTP replay against an in-scope request for that target.")
    }
    if (tls?.caPath && tls.rejectUnauthorized !== false) {
      throw new Error("Chromium cannot load network.tls.caPath directly. Install the CA in the OS trust store or explicitly set network.tls.rejectUnauthorized=false for this authorized target.")
    }
    if (tls?.rejectUnauthorized === false) output.ignoreHTTPSErrors = true
    return output
  }
}
