import type { Page } from "playwright"
import { Log } from "../../log.ts"
import { register } from "../registry.ts"
import { EMPTY_RESULT, type Detector, type DiscoveryContext, type DiscoveryResult, type Endpoint } from "../detector.ts"
import { mineEndpoints } from "../mine.ts"

const log = Log.create({ service: "hackbrowser:discovery:jsbundle" })

interface PageScripts {
  external: string[] // absolute <script src> and script preload URLs
  inline: string[] // each inline <script> body, kept separate
}

/** External scripts, module preloads, script preloads, and inline bodies on the current page. */
async function collectScripts(page: Page): Promise<PageScripts> {
  return page.evaluate(() => {
    const external = new Set<string>()
    const inline: string[] = []
    document.querySelectorAll("script").forEach((el) => {
      const src = el.src
      if (src) external.add(src)
      else if (el.textContent) inline.push(el.textContent)
    })
    document.querySelectorAll('link[rel~="modulepreload"], link[rel~="preload"][as="script"]').forEach((el) => {
      const href = (el as HTMLLinkElement).href
      if (href) external.add(href)
    })
    return { external: [...external], inline }
  })
}

/**
 * Mine endpoint candidates from every in-scope script visible in the page DOM.
 * No script-count, inline-size, or bundle-size cutoff is applied. Lazy-loaded
 * bundles are also covered by the response listener in bundle-watch.
 */
const jsbundle: Detector = {
  name: "jsbundle",
  kind: "api-call",
  timeoutMs: null,
  async applies(): Promise<boolean> {
    return true
  },
  async detect(ctx: DiscoveryContext): Promise<DiscoveryResult> {
    const origin = new URL(ctx.baseUrl).origin
    let scripts: PageScripts
    try {
      scripts = await collectScripts(ctx.page)
    } catch (error) {
      log.warn("could not enumerate page JavaScript sources", { error: String(error) })
      return EMPTY_RESULT
    }

    const endpoints = new Map<string, Endpoint>()
    const collect = (source: string): void => {
      for (const endpoint of mineEndpoints(source, origin, ctx.inScope)) {
        endpoints.set(`${endpoint.method} ${endpoint.url}`, endpoint)
      }
    }

    for (const inline of scripts.inline) {
      if (inline) collect(inline)
    }

    const inScopeExternal = scripts.external.filter((src) => {
      try {
        return ctx.inScope(new URL(src).hostname)
      } catch {
        log.warn("invalid script URL discovered in page", { src })
        return false
      }
    })
    let failedFetches = 0
    for (const src of inScopeExternal) {
      try {
        const source = await ctx.fetchText(src)
        if (!source) {
          failedFetches++
          log.warn("could not fetch discovered JavaScript source", { src })
          continue
        }
        collect(source)
      } catch (error) {
        failedFetches++
        log.warn("JavaScript source fetch failed", { src, error: String(error) })
      }
    }

    log.info("JavaScript source discovery completed", {
      inlineSources: scripts.inline.length,
      externalSources: inScopeExternal.length,
      failedFetches,
      endpointCandidates: endpoints.size,
    })
    if (endpoints.size === 0) return EMPTY_RESULT
    return { pages: [], endpoints: [...endpoints.values()], confidence: 0.5 }
  },
}

register(jsbundle)
export { jsbundle }
