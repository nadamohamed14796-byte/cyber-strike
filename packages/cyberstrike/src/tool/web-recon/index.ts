import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { Tool } from "../tool"
import { reconPhaseGate, type ReconPhase } from "../../target/recon-gate"
import { requiredPhasesForWebRecon } from "./phase"
import { TargetMemory, type Workspace } from "../../target"
import type { ScopeCheck } from "./shared"
import type { Finding, WebReconResult } from "./shared"
import {
  fullRecon,
  sitemapScan,
  robotsScan,
  openapiScan,
  graphqlProbe,
  techDetect,
  headerAudit,
  sensitiveFiles,
  corsCheck,
  methodCheck,
  openRedirect,
} from "./programs"
import { sessionScan } from "./session-scan"

const PROGRAMS = {
  session_scan: {
    description:
      "Run vulnerability tests on ALL endpoints collected by hackbrowser in the current session. Automatically performs header_audit + sensitive_files per origin, cors_check + method_check per API endpoint, and open_redirect on pages with redirect parameters. Use AFTER hackbrowser completes — does not require a target URL",
  },
  full_recon: {
    description:
      "Run all reconnaissance programs against a single target URL and return aggregated results — useful for quick standalone checks without hackbrowser",
  },
  sitemap_scan: {
    description:
      "Fetch sitemap.xml and sitemapindex, extract all declared page URLs. Follows child sitemaps up to 20 deep",
  },
  robots_scan: {
    description:
      "Parse robots.txt for Disallow/Allow paths and Sitemap references. Disallowed paths often reveal admin/API/sensitive areas",
  },
  openapi_scan: {
    description:
      "Probe 8 common OpenAPI/Swagger spec paths, parse discovered specs for all API endpoints with methods and auth schemes",
  },
  graphql_probe: {
    description:
      "Probe common GraphQL endpoints (/graphql, /api/graphql, /query, /v1/graphql, /gql) with {__typename}, test introspection",
  },
  tech_detect: {
    description:
      "Fingerprint technology stack from HTTP headers (Server, X-Powered-By), cookies (PHPSESSID, JSESSIONID), HTML patterns, and CDN/WAF indicators",
  },
  header_audit: {
    description:
      "Audit security headers: HSTS, CSP (with weakness analysis), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy. Returns score and findings",
  },
  sensitive_files: {
    description:
      "Probe for 22 sensitive files: .env, .git/HEAD, .git/config, .DS_Store, phpinfo, server-status, actuator/env, wp-config.bak, elmah.axd, trace.axd, backup.sql, web.config, crossdomain.xml. Content-validated to avoid false positives from custom 404 pages",
  },
  cors_check: {
    description:
      "Test CORS for origin reflection (evil.com), null origin bypass, wildcard with credentials. Detects cross-origin data theft vulnerabilities",
  },
  method_check: {
    description:
      "Test TRACE (XST), PUT, DELETE methods on target. Check OPTIONS Allow header for dangerous method advertisement",
  },
  open_redirect: {
    description:
      "Test 17 common redirect parameters (?url=, ?next=, ?redirect=, ?returnUrl=, etc.) for open redirect via 3xx Location, meta refresh, and JavaScript redirect",
  },
} as const satisfies Record<string, { description: string }>

type Program = keyof typeof PROGRAMS

type WebReconObservation = {
  fingerprint: string
  program: Program
  requestedTarget: string
  firstSeenAt: string
  lastSeenAt: string
  occurrences: number
  attempts: Array<{ completedAt: string; sessionID: string }>
  result: WebReconResult
}

type WebReconArtifact = {
  schemaVersion: 1
  recordType: "web-recon-results"
  canonicalTarget: string
  workspaceID: string
  workspacePath: string
  updatedAt: string
  observations: WebReconObservation[]
}

type LegacyWebReconRecord = {
  schemaVersion: 1
  recordType: "web-recon-result"
  program: Program
  requestedTarget: string
  canonicalTarget: string
  workspaceID: string
  workspacePath: string
  sessionID: string
  completedAt: string
  result: WebReconResult
}

type LegacyWebReconArtifact = {
  filename: string
  filepath: string
  rawContent: string
  record: LegacyWebReconRecord
}

function webReconFingerprint(program: Program, requestedTarget: string, result: WebReconResult): string {
  return createHash("sha256").update(JSON.stringify({ program, requestedTarget, result })).digest("hex")
}

/**
 * Read only timestamped result files produced by the old web_recon implementation.
 * Unknown, malformed, symlinked, or other-workspace files are ignored and untouched.
 */
async function loadLegacyWebReconArtifacts(
  workspace: Workspace,
  directory: string,
): Promise<LegacyWebReconArtifact[]> {
  if (directory !== "recon" && directory !== "scans") return []
  const knownPrograms = directory === "scans"
    ? ["session_scan"]
    : Object.keys(PROGRAMS).filter((program) => program !== "session_scan")
  const filenamePattern = new RegExp("^(" + knownPrograms.join("|") + ")-(\\d{4}-\\d{2}-\\d{2}T\\d{2}-\\d{2}-\\d{2}-\\d{3}Z)\\.json$")
  const output: LegacyWebReconArtifact[] = []
  let rootPath: string
  try {
    rootPath = await fs.realpath(workspace.workspacePath)
  } catch {
    return output
  }
  const directoryPath = path.join(rootPath, directory)
  let directoryInfo
  try {
    directoryInfo = await fs.lstat(directoryPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return output
    throw error
  }
  if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) return output
  const realDirectory = await fs.realpath(directoryPath)
  const relativeDirectory = path.relative(rootPath, realDirectory)
  if (relativeDirectory !== directory || path.isAbsolute(relativeDirectory)) return output

  const filenames = (await fs.readdir(realDirectory)).filter((filename) => filenamePattern.test(filename)).sort()
  for (const filename of filenames) {
    const filepath = path.join(realDirectory, filename)
    let info
    try {
      info = await fs.lstat(filepath)
    } catch {
      continue
    }
    if (info.isSymbolicLink() || !info.isFile()) continue
    const rawContent = await fs.readFile(filepath, "utf-8")
    let parsed: unknown
    try {
      parsed = JSON.parse(rawContent)
    } catch {
      continue
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue
    const record = parsed as Partial<LegacyWebReconRecord>
    const match = filenamePattern.exec(filename)
    if (
      !match ||
      record.schemaVersion !== 1 ||
      record.recordType !== "web-recon-result" ||
      typeof record.program !== "string" ||
      record.program !== match[1] ||
      !knownPrograms.includes(record.program) ||
      record.canonicalTarget !== workspace.targetURL ||
      record.workspaceID !== workspace.id ||
      typeof record.requestedTarget !== "string" ||
      typeof record.workspacePath !== "string" ||
      typeof record.sessionID !== "string" ||
      typeof record.completedAt !== "string" ||
      !Number.isFinite(Date.parse(record.completedAt)) ||
      !record.result ||
      typeof record.result !== "object" ||
      typeof record.result.output !== "string" ||
      !Array.isArray(record.result.findings)
    ) continue
    output.push({
      filename,
      filepath,
      rawContent,
      record: record as LegacyWebReconRecord,
    })
  }
  return output.sort((a, b) => Date.parse(a.record.completedAt) - Date.parse(b.record.completedAt))
}

function addWebReconObservation(
  artifact: WebReconArtifact,
  input: {
    program: Program
    requestedTarget: string
    completedAt: string
    sessionID: string
    result: WebReconResult
  },
): void {
  const fingerprint = webReconFingerprint(input.program, input.requestedTarget, input.result)
  const attempt = { completedAt: input.completedAt, sessionID: input.sessionID }
  const existing = artifact.observations.find((item) => item.fingerprint === fingerprint)
  if (!existing) {
    artifact.observations.push({
      fingerprint,
      program: input.program,
      requestedTarget: input.requestedTarget,
      firstSeenAt: input.completedAt,
      lastSeenAt: input.completedAt,
      occurrences: 1,
      attempts: [attempt],
      result: input.result,
    })
    return
  }
  if (!existing.attempts.some((item) => item.completedAt === attempt.completedAt && item.sessionID === attempt.sessionID)) {
    existing.attempts.push(attempt)
    existing.attempts.sort((a, b) => Date.parse(a.completedAt) - Date.parse(b.completedAt))
  }
  existing.occurrences = existing.attempts.length
  if (Date.parse(input.completedAt) < Date.parse(existing.firstSeenAt)) existing.firstSeenAt = input.completedAt
  if (Date.parse(input.completedAt) > Date.parse(existing.lastSeenAt)) existing.lastSeenAt = input.completedAt
}

/**
 * Delete old files only when their full result and attempt metadata are verified
 * in the stable aggregate. Re-read and byte-compare each source before removing it.
 */
async function removeMigratedLegacyArtifacts(
  workspace: Workspace,
  stablePath: string,
  legacyFiles: LegacyWebReconArtifact[],
): Promise<void> {
  if (legacyFiles.length === 0) return
  let parsed: unknown
  try {
    parsed = JSON.parse(await fs.readFile(stablePath, "utf-8"))
  } catch {
    return
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return
  const aggregate = parsed as Partial<WebReconArtifact>
  if (
    aggregate.schemaVersion !== 1 ||
    aggregate.recordType !== "web-recon-results" ||
    aggregate.workspaceID !== workspace.id ||
    aggregate.canonicalTarget !== workspace.targetURL ||
    !Array.isArray(aggregate.observations)
  ) return

  for (const legacy of legacyFiles) {
    const old = legacy.record
    const fingerprint = webReconFingerprint(old.program, old.requestedTarget, old.result)
    const observation = aggregate.observations.find((item) => item.fingerprint === fingerprint)
    if (!observation?.attempts.some((attempt) => attempt.completedAt === old.completedAt && attempt.sessionID === old.sessionID)) continue
    try {
      const info = await fs.lstat(legacy.filepath)
      if (info.isSymbolicLink() || !info.isFile()) continue
      if (await fs.readFile(legacy.filepath, "utf-8") !== legacy.rawContent) continue
      await fs.unlink(legacy.filepath)
    } catch {
      // Cleanup failure leaves the old copy in place; the verified aggregate remains valid.
    }
  }
}

/**
 * Save web_recon history into one stable workspace artifact per workflow family.
 * Identical snapshots are represented once with observation timestamps; distinct
 * outputs are retained as separate records. Unknown/corrupt files are never replaced.
 */
async function persistWebReconResultUnlocked(input: {
  workspace: Workspace
  filename: string
  program: Program
  requestedTarget: string
  completedAt: string
  sessionID: string
  result: WebReconResult
}): Promise<string> {
  const { workspace, filename, program, requestedTarget, completedAt, sessionID, result } = input
  const absolutePath = path.join(workspace.workspacePath, filename)
  const legacyFiles = await loadLegacyWebReconArtifacts(workspace, path.posix.dirname(filename))
  let artifact: WebReconArtifact | undefined

  try {
    const info = await fs.lstat(absolutePath)
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error("Existing web_recon history path is not a regular file: " + filename)
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(await fs.readFile(absolutePath, "utf-8"))
    } catch (error) {
      throw new Error("Existing web_recon history is not valid JSON; it was left untouched: " + filename + " (" + (error instanceof Error ? error.message : String(error)) + ")")
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Existing web_recon history has an unsupported structure; it was left untouched: " + filename)
    }
    const saved = parsed as Partial<WebReconArtifact>
    if (
      saved.schemaVersion !== 1 ||
      saved.recordType !== "web-recon-results" ||
      saved.workspaceID !== workspace.id ||
      saved.canonicalTarget !== workspace.targetURL ||
      !Array.isArray(saved.observations) ||
      saved.observations.some((item) =>
        !item || typeof item !== "object" ||
        typeof item.fingerprint !== "string" ||
        typeof item.program !== "string" ||
        typeof item.requestedTarget !== "string" ||
        typeof item.firstSeenAt !== "string" ||
        typeof item.lastSeenAt !== "string" ||
        !Number.isSafeInteger(item.occurrences) || Number(item.occurrences) < 1 ||
        !Array.isArray(item.attempts) ||
        item.attempts.some((attempt) => !attempt || typeof attempt !== "object" || typeof attempt.completedAt !== "string" || typeof attempt.sessionID !== "string") ||
        item.occurrences !== item.attempts.length ||
        !item.result || typeof item.result !== "object"
      )
    ) {
      throw new Error("Existing web_recon history does not match this workspace/schema; it was left untouched: " + filename)
    }
    artifact = saved as WebReconArtifact
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
  }

  if (!artifact) {
    artifact = {
      schemaVersion: 1,
      recordType: "web-recon-results",
      canonicalTarget: workspace.targetURL,
      workspaceID: workspace.id,
      workspacePath: workspace.workspacePath,
      updatedAt: completedAt,
      observations: [],
    }
  }

  for (const legacy of legacyFiles) {
    addWebReconObservation(artifact, {
      program: legacy.record.program,
      requestedTarget: legacy.record.requestedTarget,
      completedAt: legacy.record.completedAt,
      sessionID: legacy.record.sessionID,
      result: legacy.record.result,
    })
  }
  addWebReconObservation(artifact, { program, requestedTarget, completedAt, sessionID, result })
  artifact.workspacePath = workspace.workspacePath
  artifact.updatedAt = completedAt
  const savedPath = await TargetMemory.writeWorkspaceFile(workspace, filename, JSON.stringify(artifact, null, 2) + "\\n")
  await removeMigratedLegacyArtifacts(workspace, savedPath, legacyFiles)
  return savedPath
}

const webReconArtifactLocks = new Map<string, Promise<void>>()

async function withWebReconArtifactLock<T>(key: string, task: () => Promise<T>): Promise<T> {
  const previous = webReconArtifactLocks.get(key) ?? Promise.resolve()
  let release!: () => void
  const current = new Promise<void>((resolve) => {
    release = resolve
  })
  webReconArtifactLocks.set(key, current)
  await previous.catch(() => undefined)
  try {
    return await task()
  } finally {
    release()
    if (webReconArtifactLocks.get(key) === current) webReconArtifactLocks.delete(key)
  }
}

async function persistWebReconResult(input: {
  workspace: Workspace
  filename: string
  program: Program
  requestedTarget: string
  completedAt: string
  sessionID: string
  result: WebReconResult
}): Promise<string> {
  const artifactPath = path.join(input.workspace.workspacePath, input.filename)
  return withWebReconArtifactLock(artifactPath, () => persistWebReconResultUnlocked(input))
}

const dispatch: Record<
  Exclude<Program, "session_scan">,
  (target: string, args: string[], timeout: number, scopeCheck?: ScopeCheck) => Promise<WebReconResult>
> = {
  full_recon: fullRecon,
  sitemap_scan: sitemapScan,
  robots_scan: robotsScan,
  openapi_scan: openapiScan,
  graphql_probe: graphqlProbe,
  tech_detect: techDetect,
  header_audit: headerAudit,
  sensitive_files: sensitiveFiles,
  cors_check: corsCheck,
  method_check: methodCheck,
  open_redirect: openRedirect,
}

const CWE_MAP: Record<string, string> = {
  "WEB-OPENAPI": "CWE-200",
  "WEB-SITEMAP": "CWE-200",
  "WEB-ROBOTS": "CWE-200",
  "WEB-GRAPHQL": "CWE-200",
  "WEB-TECH": "CWE-200",
  "WEB-HDR-HSTS": "CWE-523",
  "WEB-HDR-CSP": "CWE-1021",
  "WEB-HDR-XCTO": "CWE-16",
  "WEB-HDR-XFO": "CWE-1021",
  "WEB-HDR-RP": "CWE-200",
  "WEB-HDR-PP": "CWE-16",
  "WEB-HDR-COOKIE": "CWE-614",
  "WEB-FILE": "CWE-538",
  "WEB-CORS": "CWE-942",
  "WEB-METHOD": "CWE-749",
  "WEB-REDIR": "CWE-601",
}

function resolveCwe(checkId: string): string | undefined {
  for (const prefix of Object.keys(CWE_MAP).sort((a, b) => b.length - a.length)) {
    if (checkId.startsWith(prefix)) return CWE_MAP[prefix]
  }
  return undefined
}

function formatOutput(program: string, result: WebReconResult): { output: string; enriched: Finding[] } {
  const enriched = result.findings.map((f) => ({
    ...f,
    severity: f.severity.toLowerCase(),
    cwe: f.cwe || resolveCwe(f.checkId),
  }))

  const output =
    enriched.length > 0
      ? result.output +
        "\n\n=== FINDINGS (" +
        enriched.length +
        ") ===\n" +
        enriched
          .map(
            (f, i) =>
              `[${i + 1}] ${f.severity} — ${f.title}${f.cwe ? ` (${f.cwe})` : ""}\n    Check: ${f.checkId} | Status: ${f.status} | Resource: ${f.resource}\n    ${f.details}\n    Remediation: ${f.remediation}`,
          )
          .join("\n") +
        "\n\nTreat these as leads, not automatically valid bugs. Save INFO/LOW hardening observations and discovery results as target notes with artifact/source IDs. Call report_vulnerability only for a concrete security claim with an affected endpoint and evidence; test plausible impact/chains first, and do not raise severity without demonstrated impact. For a reportable candidate: severity (lowercase), title, description=details, recommendation=remediation" +
        (enriched.some((f) => f.cwe) ? ", cwe_id from parentheses above" : "") +
        "."
      : result.output

  return { output, enriched }
}

export const WebReconTool = Tool.define("web_recon", {
  description: `Web reconnaissance and vulnerability testing. Two modes:\n(1) session_scan — run AFTER hackbrowser, no target needed. Tests ALL collected endpoints: tech fingerprint, security headers + cookie flags, 22 sensitive file probes, CORS origin reflection + subdomain bypass, HTTP method checks, open redirect.\n(2) Individual programs against a target URL: full_recon (all-in-one), tech_detect (stack fingerprint), header_audit (HSTS/CSP/XFO), sensitive_files (.env/.git/actuator), cors_check, method_check (TRACE/PUT/DELETE), open_redirect, sitemap_scan, robots_scan, openapi_scan, graphql_probe.`,
  parameters: z.object({
    program: z
      .enum(Object.keys(PROGRAMS) as [Program, ...Program[]])
      .describe(
        "Program to run. Use session_scan after hackbrowser to test all collected endpoints. Use individual programs for targeted checks against a specific URL.",
      ),
    target: z
      .string()
      .url()
      .refine((value) => {
        try {
          const url = new URL(value)
          return (url.protocol === "http:" || url.protocol === "https:") && !url.username && !url.password
        } catch {
          return false
        }
      }, "Target must be an HTTP(S) URL without embedded credentials")
      .optional()
      .describe("Target URL (required for all programs except session_scan). All programs resolve paths relative to this origin."),
    args: z
      .array(z.string())
      .optional()
      .default([])
      .describe("Additional arguments (reserved for future per-program options)."),
    timeout_seconds: z
      .number()
      .optional()
      .default(30)
      .describe("Maximum time per HTTP request in seconds (default: 30)."),
  }),
  async execute(params, ctx) {
    const program = params.program
    const fail = (msg: string) => ({
      title: `web_recon: ${program}`,
      output: msg,
      metadata: {
        program,
        findings: [] as Finding[],
        target_workspace: undefined as string | undefined,
        artifact_path: undefined as string | undefined,
        artifact_saved: false,
        artifact_error: undefined as string | undefined,
        notes_saved: false,
        notes_error: undefined as string | undefined,
      },
    })

    let result: WebReconResult
    let targetWorkspace: Workspace | undefined
    const sessionScopeWorkspaceIDs = new Set<string>()
    if (program === "session_scan") {
      try {
        const sessionScopeCheck: ScopeCheck = async (url) => {
          const decision = await TargetMemory.checkURLScope(url)
          if (!decision.allowed || !decision.workspace) return false
          const gate = await reconPhaseGate(decision.workspace, "vulnerability_testing")
          if (!gate.allowed) return false
          sessionScopeWorkspaceIDs.add(decision.workspace.id)
          return true
        }
        result = await sessionScan(ctx.sessionID, params.timeout_seconds, ctx.abort, async (origins) => {
          await ctx.ask({
            permission: "web_recon",
            patterns: origins,
            always: origins,
            metadata: { program },
          })
        }, sessionScopeCheck)
      } catch (e) {
        return fail(`[-] session_scan failed: ${e instanceof Error ? e.message : String(e)}`)
      }
    } else {
      if (!params.target) return fail(`[-] target URL is required for ${program}. Only session_scan runs without a target.`)
      const authorization = await TargetMemory.checkURLScope(params.target)
      targetWorkspace = authorization.workspace
      if (!authorization.allowed) {
        return fail([
          "[-] Refusing active reconnaissance: " + authorization.reason,
          "Target: " + params.target,
          "No network probes were sent.",
          "Configure the official scope first with: cyberstrike target scope <url> --include <domain> --source <program> --reference <official-https-url>",
        ].join("\n"))
      }
      // Keep recon artifacts in the canonical program/root workspace. Discovered
      // origins belong in the root inventory; do not create a full child workspace
      // for each host just because it matches a wildcard. The scope decision above
      // remains authoritative for the requested URL and active tools enforce scope.

      const requiredPhases = requiredPhasesForWebRecon(program)
      let requiredPhase = requiredPhases[0]
      let gate = await reconPhaseGate(targetWorkspace!, requiredPhase)
      // If host inventory is already complete and URL collection is the active
      // phase, allow the passive technology fingerprint to contribute there.
      // Never reopen/restart the completed live_hosts_ports checkpoint.
      if (
        !gate.allowed &&
        program === "tech_detect" &&
        gate.reason.includes("current status is complete") &&
        requiredPhases[1]
      ) {
        const fallbackPhase = requiredPhases[1]
        const fallbackGate = await reconPhaseGate(targetWorkspace!, fallbackPhase)
        if (fallbackGate.allowed) {
          requiredPhase = fallbackPhase
          gate = fallbackGate
        }
      }
      if (!gate.allowed) {
        return fail([
          "[-] Recon phase gate blocked " + program + ".",
          gate.reason,
          "Checkpoint manifest: " + gate.manifestPath,
          "No network probes were sent by this program.",
          "Use recon_checkpoint to resume the ordered phases and explicitly begin " + requiredPhase + " after prerequisites are verified.",
        ].join("\n"))
      }

      await ctx.ask({
        permission: "web_recon",
        patterns: [params.target],
        always: [params.target],
        metadata: { program },
      })
      const handler = dispatch[program]
      try {
        const persistedScopeCheck: ScopeCheck = async (url) => (await TargetMemory.checkURLScope(url)).allowed
        result = await handler(params.target, params.args, params.timeout_seconds, persistedScopeCheck)
      } catch (e) {
        return fail(`[-] ${program} failed: ${e instanceof Error ? e.message : String(e)}`)
      }
    }

    if (program === "session_scan" && sessionScopeWorkspaceIDs.size > 0) {
      const allWorkspaces = TargetMemory.list()
      const byID = new Map(allWorkspaces.map((workspace) => [workspace.id, workspace]))
      const roots = new Map<string, Workspace>()
      for (const id of sessionScopeWorkspaceIDs) {
        let current = byID.get(id)
        const visited = new Set<string>()
        while (current?.parentTargetID && !visited.has(current.id)) {
          visited.add(current.id)
          current = byID.get(current.parentTargetID)
        }
        if (current) roots.set(current.id, current)
      }
      // A combined session result is saved only when all authorized probes belong
      // to a single root program. It is never copied into multiple unrelated targets.
      if (roots.size === 1) targetWorkspace = [...roots.values()][0]
    }

    const { output, enriched } = formatOutput(program, result)
    let artifactPath: string | undefined
    let artifactError: string | undefined
    let notesSaved = false
    let notesError: string | undefined
    let finalOutput = output
    if (targetWorkspace && (program === "session_scan" || params.target)) {
      const completedAt = new Date().toISOString()
      const filename = program === "session_scan" ? "scans/session-scan-results.json" : "recon/web-recon-results.json"
      const requestedTarget = params.target ?? "session_scan: authorized origins from the current session"
      try {
        // Preserve distinct result snapshots and attempt provenance in one stable
        // artifact; identical snapshots update their observation history instead of
        // producing another JSON file. Redact only a separate export/share copy.
        artifactPath = await persistWebReconResult({
          workspace: targetWorkspace,
          filename,
          program,
          requestedTarget,
          completedAt,
          sessionID: ctx.sessionID,
          result,
        })
        try {
          const note = await TargetMemory.addNote(targetWorkspace.targetURL, {
            kind: "asset",
            title: "Recon run: " + program,
            content: [
              "## Recon run summary",
              "",
              "Program: " + program,
              "Requested URL: " + requestedTarget,
              "Completed at: " + completedAt,
              "Run artifact: " + path.relative(targetWorkspace.workspacePath, artifactPath).split(path.sep).join("/"),
              "Result status: completed; the linked JSON artifact contains distinct result snapshots and their observation/attempt history.",
              "Finding-like signals returned: " + result.findings.length + " (scanner/check output is a lead, not automatic confirmation).",
              "Severity distribution: " + (["critical", "high", "medium", "low", "info"].map((severity) => {
                const count = enriched.filter((finding) => finding.severity === severity).length
                return count ? severity + "=" + count : undefined
              }).filter(Boolean).join(", ") || "no severity-tagged signals"),
              "",
              "## Signals requiring triage",
              ...(enriched.length ? enriched.slice(0, 12).flatMap((finding) => [
                "- [" + finding.severity.toUpperCase() + "/" + finding.status + "] " + finding.title,
                "  Check/resource: " + finding.checkId + " — " + finding.resource,
                "  Observed signal: " + finding.details.replace(/\s+/g, " ").slice(0, 260),
                "  Suggested remediation: " + finding.remediation.replace(/\s+/g, " ").slice(0, 180),
                "  Validation state: unconfirmed by this recon summary; verify the exact behavior with a baseline/control and document impact before approving or escalating severity.",
              ]) : ["- No finding-like signals were returned by this run. This means only that these checks found no signals; it does not prove the target is free of vulnerabilities."]),
              ...(enriched.length > 12 ? ["- " + (enriched.length - 12) + " additional signal(s) are preserved in the full run artifact."] : []),
              "",
              "## Next step",
              "Prioritize signals by plausible attacker impact and prerequisites, not by severity label alone. For INFO/LOW observations such as missing headers, keep the original evidence and test a specific, safe exploit hypothesis with a baseline/negative control. Escalate only when a reproducible security boundary violation and meaningful impact are demonstrated; otherwise retain the hardening observation with its limitations.",
            ].join("\n"),
            source: "web_recon",
            sourceURL: params.target,
            status: "observed",
            tags: ["recon", program],
            upsertByIdentity: true,
          })
          notesSaved = true
          finalOutput += "\n\n[+] Target artifact saved: " + artifactPath
          finalOutput += "\n[+] Target notes synchronized: " + targetWorkspace.workspacePath + "/notes.md"
        } catch (error) {
          notesError = error instanceof Error ? error.message : String(error)
          finalOutput += "\n\n[!] Recon artifact was saved, but notes.md summary failed: " + notesError
        }
      } catch (error) {
        artifactError = error instanceof Error ? error.message : String(error)
        finalOutput += "\n\n[!] Target artifact auto-save failed. Results were returned but were NOT confirmed persisted: " + artifactError
      }
    } else if (program === "session_scan") {
      finalOutput += "\n\n[!] session_scan results were not auto-saved because the authorized probes did not resolve to exactly one root target workspace. The combined output was left unsaved to prevent cross-target contamination."
    }
    return {
      title: `web_recon: ${program}`,
      output: finalOutput,
      metadata: {
        program,
        findings: enriched,
        target_workspace: targetWorkspace?.workspacePath,
        artifact_path: artifactPath,
        artifact_saved: Boolean(artifactPath),
        artifact_error: artifactError,
        notes_saved: notesSaved,
        notes_error: notesError,
      },
    }
  },
})
