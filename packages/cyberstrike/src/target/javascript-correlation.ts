import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { and, desc, eq, inArray } from "../storage/db"
import { Database } from "../storage/db"
import { Instance } from "../project/instance"
import { Session } from "../session"
import { SessionTable, RequestTable, RequestObservationTable, WebFunctionTable, VulnerabilityTable } from "../session/session.sql"
import { IntelEntryTable } from "../methodology/methodology.sql"
import { TargetMemory } from "./index"

function safeURL(input?: string | null): URL | undefined {
  if (!input?.trim()) return undefined
  try {
    const value = input.trim()
    // Request.host is stored as a bare hostname in legacy captures; normalize that
    // form here without treating relative paths as URLs.
    const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : value.includes("/") || value.includes("?") || value.includes("#") ? "" : "https://" + value
    if (!candidate) return undefined
    const url = new URL(candidate)
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined
    if (url.username || url.password) return undefined
    return url
  } catch {
    return undefined
  }
}

function javascriptAssetURL(input: { type?: string | null; title?: string | null; detail?: string | null; asset?: string | null; tags?: string[] | null }): URL | undefined {
  const base = safeURL(input.asset)
  if (base && /\.m?js$/i.test(base.pathname)) return base

  // Intel's asset field is usually a target host, not a JavaScript file URL.
  // Resolve an actual script path from title/detail instead of labeling the host as a JS asset.
  const text = [input.title, input.detail].filter(Boolean).join("\n")
  const absolute = /https?:\/\/[^\s"'<>),\x60]+\.(?:m?js)(?:\?[^\s"'<>)]*)?/gi
  for (const match of text.matchAll(absolute)) {
    const url = safeURL(match[0].replace(/[.,;]+$/, ""))
    if (url && /\.m?js$/i.test(url.pathname)) return url
  }

  const relative = /(?:^|[\s"'(\x60=:])((?:\/|\.{1,2}\/)?[A-Za-z0-9_@.%+/-]+\.m?js(?:\?[^\s"'<>)]*)?)/gi
  for (const match of text.matchAll(relative)) {
    const candidate = match[1]
    const direct = safeURL(candidate)
    if (direct && /\.m?js$/i.test(direct.pathname)) return direct
    if (base) {
      try {
        const resolved = new URL(candidate, base)
        if ((resolved.protocol === "http:" || resolved.protocol === "https:") && /\.m?js$/i.test(resolved.pathname)) return resolved
      } catch {}
    }
  }

  const signal = [input.type, input.title, ...(input.tags ?? [])].filter(Boolean).join(" ").toLowerCase()
  if (!/\bjavascript\b|\bjavascript[-_ ]?file\b|\bjs[-_ ]?asset\b|\bscript[-_ ]?asset\b/.test(signal)) return undefined
  const titlePath = input.title?.trim()
  if (base && titlePath && /\.m?js(?:$|[?#])/i.test(titlePath) && !/https?:\/\//i.test(titlePath)) {
    try {
      const resolved = new URL(titlePath, base)
      if (resolved.protocol === "http:" || resolved.protocol === "https:") return resolved
    } catch {}
  }
  return undefined
}

function redact(value?: string | null, max = 320): string | null {
  if (!value) return null
  return value
    .replace(/(authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[^\r\n,;]+/gi, "$1: [REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT REDACTED]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[EMAIL REDACTED]")
    .slice(0, max)
}

function sameHost(left: string | null | undefined, right: string | null | undefined) {
  const a = safeURL(left)
  const b = safeURL(right)
  return Boolean(a && b && a.hostname.toLowerCase() === b.hostname.toLowerCase())
}

function pathWithinScope(candidate: string | null | undefined, scopedPath: string): boolean {
  const value = candidate?.split(/[?#]/, 1)[0]
  if (!value) return false
  const base = scopedPath.replace(/\/$/, "") || "/"
  if (base === "/") return true
  return value === base || value.startsWith(base + "/")
}

/** Local correlation boundary only; this does not replace the existing scope engine. */
export function isJavaScriptAssetAllowed(input: {
  targetURL: string
  javascriptURL: string
  alreadyObserved?: boolean
}): boolean {
  const target = safeURL(input.targetURL)
  const script = safeURL(input.javascriptURL)
  if (!target || !script) return false
  const hostMatches = script.hostname === target.hostname || script.hostname.endsWith("." + target.hostname)
  const targetPath = target.pathname.replace(/\/$/, "") || "/"
  const pathMatches =
    targetPath === "/" ||
    script.hostname !== target.hostname ||
    pathWithinScope(script.pathname, targetPath)
  return (hostMatches && pathMatches) || input.alreadyObserved === true
}

function normalizeEndpointLiteral(value: string): string | undefined {
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > 240) return undefined
  const absolute = safeURL(trimmed)
  if (absolute) return absolute.origin + absolute.pathname
  if (!trimmed.startsWith("/")) return undefined
  const noQuery = trimmed.split(/[?#]/, 1)[0]
  const normalized = noQuery
    .replace(/\$\{[^}]+\}/g, "{param}")
    .replace(/:[A-Za-z_$][\w$]*/g, "{param}")
    .replace(/\/{2,}/g, "/")
  return normalized.length > 1 ? normalized : undefined
}

export function extractStaticJavaScriptEndpoints(content: string): string[] {
  const found = new Set<string>()
  const callArgument = /(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*["'\`]([^"'\`]{1,240})["'\`]/gi
  const routeString = /["'\`]((?:https?:\/\/)[^"'\`\s]{1,240}|\/(?:api|graphql|rest|rpc|v\d+|auth|admin|users|account|orders|cart|checkout|upload|download|search|profile)(?:\/[^"'\`\s]{0,160})?)["'\`]/gi
  for (const pattern of [callArgument, routeString]) {
    for (const match of content.matchAll(pattern)) {
      const normalized = normalizeEndpointLiteral(match[1])
      if (normalized) found.add(normalized)
      if (found.size >= 200) break
    }
    if (found.size >= 200) break
  }
  return [...found]
}

export interface JavaScriptSourceFile {
  relativePath: string
  basename: string
  sha256: string
  bytes: number
  endpointLiterals: string[]
}

/** Inventory only local JS source files; never follow symlinks or execute their contents. */
async function inventoryJavaScriptFiles(root: string): Promise<JavaScriptSourceFile[]> {
  const output: JavaScriptSourceFile[] = []
  let totalBytes = 0
  async function visit(directory: string, depth: number): Promise<void> {
    if (depth > 4 || output.length >= 250 || totalBytes >= 5 * 1024 * 1024) return
    let entries
    try {
      entries = await fs.readdir(directory, { withFileTypes: true })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return
      throw error
    }
    for (const entry of entries) {
      if (output.length >= 250 || totalBytes >= 5 * 1024 * 1024) break
      const fullPath = path.join(directory, entry.name)
      if (entry.isDirectory()) {
        await visit(fullPath, depth + 1)
        continue
      }
      if (!entry.isFile() || !/\.(?:m?js|cjs)$/i.test(entry.name)) continue
      const stat = await fs.stat(fullPath)
      if (stat.size < 0 || stat.size > 1024 * 1024 || totalBytes + stat.size > 5 * 1024 * 1024) continue
      const content = await fs.readFile(fullPath, "utf-8")
      totalBytes += Buffer.byteLength(content, "utf-8")
      output.push({
        relativePath: path.relative(path.dirname(root), fullPath).split(path.sep).join("/"),
        basename: entry.name,
        sha256: createHash("sha256").update(content).digest("hex"),
        bytes: Buffer.byteLength(content, "utf-8"),
        endpointLiterals: extractStaticJavaScriptEndpoints(content),
      })
    }
  }
  await visit(root, 0)
  return output
}

export interface JavaScriptCorrelationGraph {
  schemaVersion: 1
  createdAt: string
  targetURL: string
  sessionID: string
  javascriptAssets: Array<{
    intelEntryID: string | null
    url: string
    title: string
    discoveredBy: string | null
    confidence: string | null
    tags: string[]
  }>
  sourceFiles: JavaScriptSourceFile[]
  evidence: Array<{
    id: string
    requestID: string
    kind: "captured-response"
    responseStatus: number | null
    contentType: string | null
    responseSize: number | null
    redactedPreview: string | null
  }>
  requests: Array<{
    id: string
    method: string
    host: string | null
    url: string | null
    normalizedPath: string
    responseStatus: number | null
    responseContentType: string | null
    responseSize: number | null
    responsePreview: string | null
    hasRawRequest: boolean
  }>
  webFunctions: Array<{
    id: string
    name: string
    actionType: string
    requestID: string
    roleID: string | null
    objects: string[]
  }>
  observations: Array<{
    id: string
    requestID: string | null
    credentialID: string | null
    operationGroupHash: string
    slots: Array<{ location: string; name: string; retained?: boolean }>
  }>
  findings: Array<{
    id: string
    title: string
    severity: string
    status: string
    endpoint: string | null
  }>
  edges: Array<{ from: string; to: string; relation: string; confidence: "direct" | "candidate"; evidence: string }>
  notes: string[]
}

/**
 * Correlates JavaScript asset observations with already-recorded target requests,
 * response metadata, web-function models, request observations and findings. It
 * performs no HTTP requests and stores only redacted, size-limited response previews.
 */
export namespace JavaScriptCorrelation {
  export async function build(input: {
    sessionID: string
    targetURL: string
    javascriptURL?: string
  }): Promise<{ graph: JavaScriptCorrelationGraph; workspacePath: string; graphPath: string; noteID: string }> {
    const rootSessionID = Session.root(input.sessionID)
    const normalizedTarget = TargetMemory.normalize(input.targetURL)
    const explicitJS = input.javascriptURL ? safeURL(input.javascriptURL) : undefined
    if (input.javascriptURL && !explicitJS) throw new Error("javascriptURL must be a valid HTTP(S) URL without embedded credentials.")
    const workspace = await TargetMemory.ensure(input.targetURL)
    const sourceFiles = await inventoryJavaScriptFiles(path.join(workspace.workspacePath, "javascript"))

    const projectID = Instance.project.id
    const sessionIDsSet = new Set<string>([rootSessionID])
    let frontier = [rootSessionID]
    while (frontier.length > 0) {
      const children = Database.use((db) =>
        db
          .select({ id: SessionTable.id })
          .from(SessionTable)
          .where(and(eq(SessionTable.project_id, projectID), inArray(SessionTable.parent_id, frontier)))
          .all()
          .map((row) => row.id)
          .filter((id) => !sessionIDsSet.has(id)),
      )
      for (const child of children) sessionIDsSet.add(child)
      frontier = children
    }
    const sessionIDs = [...sessionIDsSet]

    const intel = Database.use((db) =>
      db
        .select()
        .from(IntelEntryTable)
        .where(inArray(IntelEntryTable.session_id, sessionIDs))
        .orderBy(desc(IntelEntryTable.time_updated))
        .limit(1000)
        .all(),
    )
    const jsCandidates = intel
      .map((row) => ({
        row,
        url: javascriptAssetURL({
          type: row.type,
          title: row.title,
          detail: row.detail,
          asset: row.asset,
          tags: row.tags as string[] | null,
        }),
      }))
      .filter((item): item is { row: typeof intel[number]; url: URL } => Boolean(item.url))

    const targetURL = new URL(normalizedTarget.targetURL)
    const targetPath = targetURL.pathname.replace(/\/$/, "") || "/"
    if (explicitJS) {
      const explicitKey = explicitJS.origin + explicitJS.pathname
      const alreadyObserved = jsCandidates.some((item) => item.url.origin + item.url.pathname === explicitKey)
      if (!isJavaScriptAssetAllowed({
        targetURL: normalizedTarget.targetURL,
        javascriptURL: explicitJS.href,
        alreadyObserved,
      })) {
        throw new Error("JavaScript asset is outside the target path/host boundary and is not already observed in this session. This correlation tool does not replace the existing scope engine.")
      }
      if (!alreadyObserved) {
        jsCandidates.unshift({
          row: {
            id: null as unknown as string,
            type: "javascript_file",
            title: explicitJS.pathname.split("/").pop() || explicitJS.href,
            asset: explicitJS.href,
            source: "explicit analyst input",
            confidence_level: "unverified",
            tags: ["javascript", "explicit-input"],
          } as typeof intel[number],
          url: explicitJS,
        })
      }
    }
    const filteredAssets = explicitJS
      ? jsCandidates.filter((item) => item.url.origin + item.url.pathname === explicitJS.origin + explicitJS.pathname)
      : jsCandidates.filter((item) => {
          const hostMatches = item.url.hostname === targetURL.hostname || item.url.hostname.endsWith("." + targetURL.hostname)
          if (!hostMatches) return false
          // For a path-scoped application, ignore scripts from sibling applications
          // mounted on the same hostname.
          if (item.url.hostname === targetURL.hostname && targetPath !== "/" && !pathWithinScope(item.url.pathname, targetPath)) return false
          return true
        })
    const seenAssets = new Set<string>()
    const assets = filteredAssets.filter((item) => {
      const key = item.url.origin + item.url.pathname
      if (seenAssets.has(key)) return false
      seenAssets.add(key)
      return true
    }).slice(0, 150)

    const requests = Database.use((db) =>
      db
        .select()
        .from(RequestTable)
        .where(inArray(RequestTable.session_id, sessionIDs))
        .orderBy(desc(RequestTable.time_updated))
        .limit(2000)
        .all(),
    )
    const relevantRequests = requests.filter((request) => {
      const hostURL = safeURL(request.origin) ?? safeURL(request.page_url) ?? safeURL(request.host)
      if (!hostURL) return false
      const host = hostURL.hostname.toLowerCase()
      const isTargetHost = host === targetURL.hostname || host.endsWith("." + targetURL.hostname)
      if (isTargetHost) {
        // When the target is a path-scoped app, don't pull sibling applications' records
        // from the same host unless the observed page itself belongs to the scoped path.
        if (host === targetURL.hostname && targetPath !== "/") {
          const pageURL = safeURL(request.page_url)
          const requestPathMatches = pathWithinScope(request.normalized_path, targetPath)
          const pagePathMatches = pageURL?.hostname === targetURL.hostname && pathWithinScope(pageURL.pathname, targetPath)
          if (!requestPathMatches && !pagePathMatches) return false
        }
        return true
      }
      return assets.some((asset) => asset.url.hostname.toLowerCase() === host)
    })
    const requestIDs = relevantRequests.map((request) => request.id)
    const requestIDSet = new Set(requestIDs)
    const webFunctions = requestIDs.length
      ? Database.use((db) =>
          db
            .select()
            .from(WebFunctionTable)
            .where(inArray(WebFunctionTable.request_id, requestIDs))
            .orderBy(desc(WebFunctionTable.time_updated))
            .limit(1000)
            .all(),
        )
      : []
    const observations = requestIDs.length
      ? Database.use((db) =>
          db
            .select()
            .from(RequestObservationTable)
            .where(and(inArray(RequestObservationTable.session_id, sessionIDs), inArray(RequestObservationTable.request_id, requestIDs)))
            .orderBy(desc(RequestObservationTable.time_updated))
            .limit(2000)
            .all(),
        )
      : []
    const findings = Database.use((db) =>
      db
        .select()
        .from(VulnerabilityTable)
        .where(inArray(VulnerabilityTable.session_id, sessionIDs))
        .orderBy(desc(VulnerabilityTable.time_updated))
        .limit(500)
        .all(),
    ).filter((finding) => {
      if (!finding.endpoint) return false
      const endpoint = finding.endpoint.trim()
      if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
        const endpointURL = safeURL(endpoint)
        if (!endpointURL) return false
        const isTargetHost = endpointURL.hostname === targetURL.hostname || endpointURL.hostname.endsWith("." + targetURL.hostname)
        if (isTargetHost) {
          return targetPath === "/" || pathWithinScope(endpointURL.pathname, targetPath)
        }
        return assets.some((asset) => sameHost(endpoint, asset.url.href))
      }
      return relevantRequests.some((request) => request.normalized_path === endpoint || request.normalized_path.includes(endpoint) || endpoint.includes(request.normalized_path))
    })

    const graph: JavaScriptCorrelationGraph = {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      targetURL: normalizedTarget.targetURL,
      sessionID: rootSessionID,
      javascriptAssets: assets.map((item) => ({
        intelEntryID: item.row.id ?? null,
        url: item.url.origin + item.url.pathname,
        title: item.row.title,
        discoveredBy: item.row.source ?? null,
        confidence: item.row.confidence_level ?? null,
        tags: (item.row.tags as string[] | null) ?? [],
      })),
      sourceFiles,
      evidence: relevantRequests
        .filter((request) => request.response_status !== null || Boolean(request.processed_response))
        .map((request) => ({
          id: "response:" + request.id,
          requestID: request.id,
          kind: "captured-response" as const,
          responseStatus: request.response_status ?? null,
          contentType: request.response_content_type ?? null,
          responseSize: request.response_size ?? null,
          redactedPreview: redact(request.processed_response),
        })),
      requests: relevantRequests.map((request) => {
        // Older captures may have host/page_url but no normalized origin. Build
        // a URL only from an observed base; never invent a host for path-only rows.
        const base = safeURL(request.origin) ?? safeURL(request.page_url) ?? safeURL(request.host)
        let observedURL: string | null = null
        if (base) {
          try {
            observedURL = new URL(request.normalized_path, base).href
          } catch {
            observedURL = null
          }
        }
        return {
          id: request.id,
          method: request.method,
          host: request.host ?? base?.host ?? null,
          url: observedURL,
          normalizedPath: request.normalized_path,
          responseStatus: request.response_status ?? null,
          responseContentType: request.response_content_type ?? null,
          responseSize: request.response_size ?? null,
          responsePreview: redact(request.processed_response),
          hasRawRequest: Boolean(request.raw_request),
        }
      }),
      webFunctions: webFunctions.map((fn) => ({
        id: fn.id,
        name: fn.name,
        actionType: fn.action_type,
        requestID: fn.request_id,
        roleID: fn.role_id ?? null,
        objects: (fn.objects as string[] | null) ?? [],
      })),
      observations: observations.map((row) => ({
        id: row.id,
        requestID: row.request_id ?? null,
        credentialID: row.credential_id ?? null,
        operationGroupHash: row.op_group_hash,
        slots: ((row.slots as Array<{loc:string;name:string;value?:string;retained?:boolean}> | null) ?? []).map((slot) => ({
          location: slot.loc,
          name: slot.name,
          retained: slot.retained,
        })),
      })),
      findings: findings.map((finding) => ({
        id: finding.id,
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        endpoint: finding.endpoint ?? null,
      })),
      edges: [],
      notes: [],
    }

    const assetBasenames = new Map(graph.javascriptAssets.map((asset) => [path.posix.basename(new URL(asset.url).pathname).toLowerCase(), asset.url]))
    for (const file of graph.sourceFiles) {
      const matchedURL = assetBasenames.get(file.basename.toLowerCase())
      if (matchedURL) {
        graph.edges.push({
          from: "javascript-file:" + file.relativePath,
          to: "javascript:" + matchedURL,
          relation: "basename-match",
          confidence: "candidate",
          evidence: "Local file and observed asset share a basename; verify the content/hash before treating them as identical.",
        })
      }
      for (const endpoint of file.endpointLiterals) {
        const endpointURL = safeURL(endpoint)
        const endpointPath = endpointURL?.pathname ?? endpoint.split(/[?#]/, 1)[0]
        for (const request of graph.requests) {
          const observedPath = request.normalizedPath
          const requestHost = safeURL(request.url)?.hostname ?? safeURL(request.host)?.hostname
          if (endpointURL && requestHost !== endpointURL.hostname) continue
          const base = endpointPath.replace(/\{param\}/g, "").replace(/\/$/, "")
          if (base.length > 4 && (observedPath === endpointPath || observedPath.startsWith(base + "/") || endpointPath.startsWith(observedPath.replace(/\{[^}]+\}/g, "")))) {
            graph.edges.push({
              from: "javascript-file:" + file.relativePath,
              to: "request:" + request.id,
              relation: "static-endpoint-literal-match",
              confidence: "candidate",
              evidence: "Static endpoint literal was found in the JavaScript source and overlaps the captured normalized path; execution is not proven.",
            })
          }
        }
      }
    }
    for (const response of graph.evidence) {
      graph.edges.push({
        from: "request:" + response.requestID,
        to: "evidence:" + response.id,
        relation: "captured-response-evidence",
        confidence: "direct",
        evidence: "Response status/content metadata is linked to the request record in SQLite.",
      })
    }

    for (const asset of graph.javascriptAssets) {
      for (const request of graph.requests) {
        const reqHost = safeURL(request.url)?.hostname
        const assetHost = safeURL(asset.url)?.hostname
        if (reqHost && assetHost && reqHost === assetHost) {
          graph.edges.push({
            from: "javascript:" + asset.url,
            to: "request:" + request.id,
            relation: "same-host-observation",
            confidence: "candidate",
            evidence: "Host match only; this does not prove the JavaScript file issued the request.",
          })
        }
      }
    }
    for (const fn of graph.webFunctions) {
      if (requestIDSet.has(fn.requestID)) {
        graph.edges.push({
          from: "request:" + fn.requestID,
          to: "web-function:" + fn.id,
          relation: "request-backs-web-function",
          confidence: "direct",
          evidence: "web_function.request_id foreign-key relationship",
        })
      }
    }
    for (const observation of graph.observations) {
      if (observation.requestID && requestIDSet.has(observation.requestID)) {
        graph.edges.push({
          from: "request:" + observation.requestID,
          to: "observation:" + observation.id,
          relation: "request-has-observation",
          confidence: "direct",
          evidence: "request_observation.request_id foreign-key relationship",
        })
      }
    }
    for (const finding of graph.findings) {
      const matching = graph.requests.filter((request) => {
        const endpoint = (finding.endpoint ?? "").trim()
        return endpoint === request.normalizedPath ||
          request.normalizedPath === endpoint ||
          (endpoint.startsWith("/") && request.normalizedPath.startsWith(endpoint)) ||
          (endpoint.length > 2 && request.normalizedPath.includes(endpoint))
      })
      for (const request of matching) {
        graph.edges.push({
          from: "request:" + request.id,
          to: "finding:" + finding.id,
          relation: "endpoint-pattern-match",
          confidence: "candidate",
          evidence: "Finding endpoint string matched normalized request path; manually verify the match.",
        })
      }
    }
    graph.notes.push("Local JavaScript files are hashed and scanned only for static URL/path literals; source code is never copied into the graph.")
    graph.notes.push("No JavaScript source was downloaded or executed by this correlation operation.")
    graph.notes.push("Host-only JavaScript-to-request edges are candidate relationships, not proof the script caused or called the endpoint.")
    graph.notes.push("Response previews are length-limited and redacted heuristically; the original captured request/response remains the source of evidence in the session database.")
    graph.notes.push("This graph only correlates observations already stored in the current session tree; missing edges do not prove that a relationship does not exist.")

    const urlList = graph.javascriptAssets.map((asset) => asset.url).join("\n")
    const content = [
      "# JavaScript Correlation Snapshot",
      "",
      "- Target: " + workspace.targetURL,
      "- Session: " + rootSessionID,
      "- JavaScript asset URLs: " + graph.javascriptAssets.length,
      "- Local JavaScript source files indexed: " + graph.sourceFiles.length,
      "- Static endpoint literals extracted: " + graph.sourceFiles.reduce((sum, file) => sum + file.endpointLiterals.length, 0),
      "- Captured response evidence nodes: " + graph.evidence.length,
      "- Related captured requests: " + graph.requests.length,
      "- Web functions: " + graph.webFunctions.length,
      "- Request observations: " + graph.observations.length,
      "- Candidate findings: " + graph.findings.length,
      "- Recorded graph edges: " + graph.edges.length,
      "",
      "## Local JavaScript files",
      ...(graph.sourceFiles.length ? graph.sourceFiles.map((file) => "- " + file.relativePath + " — SHA-256 " + file.sha256 + " — " + file.bytes + " bytes — " + file.endpointLiterals.length + " static endpoint literal(s)") : ["No local .js/.mjs/.cjs source files found in the target workspace."]),
      "",
      "## JavaScript assets",
      ...(urlList ? [urlList] : ["No JavaScript asset matched the current stored Intel. Provide --javascript-url or record an asset with add_intel first."]),
      "",
      "## Notes about relationship confidence",
      ...graph.notes.map((note) => "- " + note),
      "",
      "## Findings matched by endpoint pattern",
      ...graph.findings.map((finding) => "- " + finding.id + " [" + finding.status + "/" + finding.severity + "] " + finding.title + " — " + (finding.endpoint ?? "no endpoint")),
    ].join("\n")
    const note = await TargetMemory.addNote(workspace.targetURL, {
      kind: "javascript",
      title: "JavaScript correlation snapshot - " + rootSessionID + (explicitJS ? " - " + explicitJS.pathname : " - all assets"),
      content,
      source: "session:" + rootSessionID,
      sourceURL: explicitJS?.href,
      status: "observed",
      tags: ["javascript", "correlation", "request-response", "finding"],
    })

    const filenameHost = (explicitJS?.hostname ?? new URL(workspace.targetURL).hostname).replace(/[^a-z0-9.-]/gi, "-").slice(0, 50)
    const snapshotSelector = explicitJS ? explicitJS.origin + explicitJS.pathname : "all-assets"
    const digest = createHash("sha256").update(JSON.stringify([workspace.targetURL, rootSessionID, snapshotSelector])).digest("hex").slice(0, 12)
    const graphPath = path.join(workspace.workspacePath, "javascript", filenameHost + "-" + digest + ".json")
    await fs.mkdir(path.dirname(graphPath), { recursive: true })
    // Generated graph path is stable per target/session/selector; refresh it instead
    // of growing an unbounded collection of identical timestamped snapshots.
    await fs.writeFile(graphPath, JSON.stringify(graph, null, 2) + "\n", "utf-8")
    return { graph, workspacePath: workspace.workspacePath, graphPath, noteID: note.note.id }
  }
}
