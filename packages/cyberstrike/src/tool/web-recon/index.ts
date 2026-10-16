import z from "zod"
import path from "node:path"
import { Tool } from "../tool"
import { reconPhaseGate, type ReconPhase } from "../../target/recon-gate"
import { TargetMemory, type Workspace } from "../../target"
import { redactTargetNoteSecrets } from "../../target/redact"
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
      // A host covered by a root wildcard gets its own nested workspace before outputs
      // are produced; exact-host target workspaces keep their path-scoped identity.
      try {
        const requestedURL = new URL(params.target)
        if (targetWorkspace &&
            requestedURL.hostname !== targetWorkspace.hostname &&
            requestedURL.hostname.toLowerCase().endsWith("." + targetWorkspace.hostname.toLowerCase())) {
          const child = await TargetMemory.registerObservedAsset(requestedURL.origin, "subdomain")
          if (!child) {
            return fail("[-] Scope matched but this subdomain could not be attached under its authorized parent. No network probes were sent and no artifact was written.")
          }
          targetWorkspace = child
        }
        // A program may list an additional non-subdomain host as an explicit scope item.
        // Keep those results under the authorizing program workspace rather than falsely
        // nesting the unrelated hostname or manufacturing a second authorization manifest.
      } catch (error) {
        return fail("[-] Could not prepare the canonical target workspace before reconnaissance: " + (error instanceof Error ? error.message : String(error)) + ". No network probes were sent.")
      }

      const requiredPhase: ReconPhase =
        ["sitemap_scan", "robots_scan", "openapi_scan"].includes(program)
          ? "url_collection"
          : program === "tech_detect"
            ? "live_hosts_ports"
            : "vulnerability_testing"
      const gate = await reconPhaseGate(targetWorkspace!, requiredPhase)
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
      const artifactDirectory = program === "session_scan" ? "scans" : "recon"
      const filename = artifactDirectory + "/" + program + "-" + completedAt.replace(/[:.]/g, "-") + ".json"
      const record = {
        schemaVersion: 1,
        recordType: "web-recon-result",
        program,
        requestedTarget: params.target ?? "session_scan: authorized origins from the current session",
        canonicalTarget: targetWorkspace.targetURL,
        workspaceID: targetWorkspace.id,
        workspacePath: targetWorkspace.workspacePath,
        sessionID: ctx.sessionID,
        completedAt,
        result,
      }
      try {
        const content = redactTargetNoteSecrets(JSON.stringify(record, null, 2)) + "\n"
        artifactPath = await TargetMemory.writeWorkspaceFile(targetWorkspace, filename, content)
        try {
          const note = await TargetMemory.addNote(targetWorkspace.targetURL, {
            kind: "asset",
            title: "Recon run: " + program,
            content: [
              "Program: " + program,
              "Requested URL: " + (params.target ?? "authorized origins from the current session"),
              "Completed at: " + completedAt,
              "Run artifact: " + path.relative(targetWorkspace.workspacePath, artifactPath).split(path.sep).join("/"),
              "Result status: completed; detailed output is in the linked JSON artifact.",
              "Finding-like signals returned: " + result.findings.length + " (not automatically confirmed as vulnerabilities).",
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
