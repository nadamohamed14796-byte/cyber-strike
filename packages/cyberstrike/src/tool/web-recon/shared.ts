export type Finding = {
  checkId: string
  provider: string
  severity: string
  status: string
  resource: string
  title: string
  details: string
  remediation: string
  cwe?: string
}

export type WebReconResult = { output: string; findings: Finding[] }

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

const MAX_BODY = 2_000_000

export type FetchResult = { status: number; headers: Headers; text: string }

/**
 * Fetch only a caller-selected HTTP(S) URL. Redirects are deliberately not
 * followed automatically: a target-controlled Location header must never turn
 * an approved probe into an unreviewed request to another host.
 */
export async function safeFetch(
  url: string,
  opts: { timeout?: number; method?: string; body?: string; headers?: Record<string, string>; redirect?: "manual" } = {},
): Promise<FetchResult | null> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return null
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password) return null

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), (opts.timeout ?? 10) * 1000)
  try {
    const resp = await fetch(parsed.href, {
      method: opts.method ?? "GET",
      headers: { "User-Agent": UA, Accept: "*/*", ...opts.headers },
      body: opts.body,
      signal: controller.signal,
      redirect: "manual",
    })
    const declared = Number(resp.headers.get("content-length") ?? "0")
    if (Number.isFinite(declared) && declared > MAX_BODY) {
      await resp.body?.cancel()
      return { status: resp.status, headers: resp.headers, text: "" }
    }

    // Bound bytes while reading, not only after response.text() has downloaded
    // an unbounded body. This also covers responses without Content-Length.
    const reader = resp.body?.getReader()
    if (!reader) return { status: resp.status, headers: resp.headers, text: "" }
    const chunks: Uint8Array[] = []
    let size = 0
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      const remaining = MAX_BODY - size
      if (remaining <= 0) {
        await reader.cancel()
        break
      }
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value
      chunks.push(chunk)
      size += chunk.byteLength
      if (value.byteLength > remaining || size >= MAX_BODY) {
        await reader.cancel()
        break
      }
    }
    const bytes = new Uint8Array(size)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }
    return { status: resp.status, headers: resp.headers, text: new TextDecoder().decode(bytes) }
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

export function extractLocs(xml: string): string[] {
  const locs: string[] = []
  const re = /<loc>\s*(?:<!\[CDATA\[\s*)?([^<\]\s]+)/gi
  let match: RegExpExecArray | null
  while ((match = re.exec(xml)) !== null) {
    if (match[1]) locs.push(match[1])
  }
  return locs
}
