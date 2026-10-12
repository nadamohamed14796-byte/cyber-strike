import z from "zod"
import { Tool } from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { abortAfterAny } from "../util/abort"
import { Identifier } from "../id/id"

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes

export const WebFetchTool = Tool.define("webfetch", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("The URL to fetch content from"),
    format: z
      .enum(["text", "markdown", "html"])
      .default("markdown")
      .describe("The format to return the content in (text, markdown, or html). Defaults to markdown."),
    timeout: z.number().describe("Optional timeout in seconds (max 120)").optional(),
  }),
  async execute(params, ctx) {
    let current = parseHttpURL(params.url)

    await ctx.ask({
      permission: "webfetch",
      patterns: [current.href],
      always: ["*"],
      metadata: {
        url: current.href,
        format: params.format,
        timeout: params.timeout,
      },
    })

    const timeout = Math.max(1, Math.min((params.timeout ?? DEFAULT_TIMEOUT / 1000) * 1000, MAX_TIMEOUT))

    // Build Accept header based on requested format with q parameters for fallbacks
    let acceptHeader = "*/*"
    switch (params.format) {
      case "markdown":
        acceptHeader = "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
        break
      case "text":
        acceptHeader = "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
        break
      case "html":
        acceptHeader = "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
        break
      default:
        acceptHeader =
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    }
    const headers = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
      Accept: acceptHeader,
      "Accept-Language": "en-US,en;q=0.9",
    }

    // Permission is checked for the initial URL above and for every redirect below.
    // Network time is bounded across hops; time spent waiting for a redirect approval
    // does not consume the network budget.
    let networkElapsed = 0
    let redirects = 0
    while (true) {
      const remaining = timeout - networkElapsed
      if (remaining <= 0) throw new Error("Request timed out before the response completed")
      const started = Date.now()
      const { signal, clearTimeout } = abortAfterAny(remaining, ctx.abort)
      let nextURL: URL | undefined

      try {
        let response = await fetch(current, { signal, headers, redirect: "manual" })

        // Retry a Cloudflare bot challenge with an honest user agent. Keep redirects
        // manual on the retry too so it cannot bypass destination permission checks.
        if (response.status === 403 && response.headers.get("cf-mitigated") === "challenge") {
          await response.body?.cancel().catch(() => undefined)
          response = await fetch(current, {
            signal,
            headers: { ...headers, "User-Agent": "cyberstrike" },
            redirect: "manual",
          })
        }

        if ([301, 302, 303, 307, 308].includes(response.status)) {
          const location = response.headers.get("location")
          await response.body?.cancel().catch(() => undefined)
          if (!location) throw new Error("Redirect response did not include a Location header")
          if (redirects >= MAX_REDIRECTS) throw new Error("Too many redirects (maximum 5)")
          nextURL = parseHttpURL(new URL(location, current))
        } else {
          if (!response.ok) {
            await response.body?.cancel().catch(() => undefined)
            throw new Error(\`Request failed with status code: \${response.status}\`)
          }

          // Fail early when a trustworthy length is provided, but always enforce the
          // same cap while streaming because Content-Length may be absent or wrong.
          const contentLength = response.headers.get("content-length")
          const declaredLength = contentLength ? Number(contentLength) : 0
          if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_SIZE) {
            await response.body?.cancel().catch(() => undefined)
            throw new Error("Response too large (exceeds 5MB limit)")
          }

          const bytes = await readBoundedBytes(response.body, MAX_RESPONSE_SIZE)
          const contentType = response.headers.get("content-type") || ""
          const mime = contentType.split(";")[0]?.trim().toLowerCase() || ""
          const title = \`\${current.href} (\${contentType})\`

          // Check if response is an image
          const isImage = mime.startsWith("image/") && mime !== "image/svg+xml" && mime !== "image/vnd.fastbidsheet"

          if (isImage) {
            const base64Content = Buffer.from(bytes).toString("base64")
            return {
              title,
              output: "Image fetched successfully",
              metadata: {},
              attachments: [
                {
                  id: Identifier.ascending("part"),
                  sessionID: ctx.sessionID,
                  messageID: ctx.messageID,
                  type: "file",
                  mime,
                  url: \`data:\${mime};base64,\${base64Content}\`,
                },
              ],
            }
          }

          const text = new TextDecoder().decode(bytes)

          // Handle content based on requested format and actual content type
          switch (params.format) {
            case "markdown":
              if (contentType.includes("text/html")) {
                const markdown = convertHTMLToMarkdown(text)
                return { output: markdown, title, metadata: {} }
              }
              return { output: text, title, metadata: {} }

            case "text":
              if (contentType.includes("text/html")) {
                const extracted = await extractTextFromHTML(text)
                return { output: extracted, title, metadata: {} }
              }
              return { output: text, title, metadata: {} }

            case "html":
              return { output: text, title, metadata: {} }

            default:
              return { output: text, title, metadata: {} }
          }
        }
      } finally {
        clearTimeout()
        networkElapsed += Date.now() - started
      }

      if (!nextURL) throw new Error("Redirect handling failed without a destination")
      if (networkElapsed >= timeout) throw new Error("Request timed out before redirect approval")
      await ctx.ask({
        permission: "webfetch",
        patterns: [nextURL.href],
        always: ["*"],
        metadata: {
          url: nextURL.href,
          redirectedFrom: current.href,
          format: params.format,
          timeout: params.timeout,
        },
      })
      current = nextURL
      redirects++
    }
  },
  },
})

function parseHttpURL(input: string | URL): URL {
  let url: URL
  try {
    url = input instanceof URL ? new URL(input.href) : new URL(input)
  } catch {
    throw new Error("URL must be an absolute HTTP(S) URL")
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    !url.hostname ||
    url.username ||
    url.password
  ) {
    throw new Error("URL must be an HTTP(S) URL without embedded credentials")
  }
  return url
}

async function readBoundedBytes(body: ReadableStream<Uint8Array> | null, maximum: number): Promise<Uint8Array> {
  if (!body) return new Uint8Array()
  const reader = body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const item = await reader.read()
      if (item.done) break
      total += item.value.byteLength
      if (total > maximum) {
        await reader.cancel().catch(() => undefined)
        throw new Error("Response too large (exceeds 5MB limit)")
      }
      chunks.push(item.value)
    }
  } finally {
    reader.releaseLock()
  }

  const result = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.byteLength
  }
  return result
}

async function extractTextFromHTML(html: string) {
  let text = ""
  let skipContent = false

  const rewriter = new HTMLRewriter()
    .on("script, style, noscript, iframe, object, embed", {
      element() {
        skipContent = true
      },
      text() {
        // Skip text content inside these elements
      },
    })
    .on("*", {
      element(element) {
        // Reset skip flag when entering other elements
        if (!["script", "style", "noscript", "iframe", "object", "embed"].includes(element.tagName)) {
          skipContent = false
        }
      },
      text(input) {
        if (!skipContent) {
          text += input.text
        }
      },
    })
    .transform(new Response(html))

  await rewriter.text()
  return text.trim()
}

function convertHTMLToMarkdown(html: string): string {
  const turndownService = new TurndownService({
    headingStyle: "atx",
    hr: "---",
    bulletListMarker: "-",
    codeBlockStyle: "fenced",
    emDelimiter: "*",
  })
  turndownService.remove(["script", "style", "meta", "link"])
  return turndownService.turndown(html)
}
