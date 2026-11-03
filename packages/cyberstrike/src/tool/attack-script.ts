import z from "zod"
import { Tool } from "./tool"
import { TargetMemory } from "../target"
import { reconPhaseGate } from "../target/recon-gate"
import path from "path"
import fs from "node:fs/promises"

async function resolveScriptsDir(): Promise<{ directory: string; searched: string[] }> {
  // process.execPath can be a symlink (for example ~/.local/bin/cyberstrike).
  // Release archives put data/scripts beside the real binary, so inspect both
  // the invoked path and its canonical path before falling back to source layouts.
  const executablePath = await fs.realpath(process.execPath).catch(() => process.execPath)
  const home = process.env.HOME ?? process.env.USERPROFILE
  const xdgDataHome = process.env.XDG_DATA_HOME || (home ? path.join(home, ".local", "share") : undefined)
  const candidates = [
    path.join(path.dirname(executablePath), "data", "scripts"),
    path.join(path.dirname(process.execPath), "data", "scripts"),
    path.resolve(import.meta.dir, "../../data/scripts"),
    path.resolve(import.meta.dir, "data/scripts"),
    ...(xdgDataHome ? [
      path.join(xdgDataHome, "cyberstrike", "data", "scripts"),
      path.join(xdgDataHome, "cyberstrike", "scripts"),
    ] : []),
  ]
  const searched = [...new Set(candidates)]
  for (const candidate of searched) {
    try {
      const info = await fs.stat(candidate)
      if (info.isDirectory()) return { directory: candidate, searched }
    } catch {
      // Try the next supported layout.
    }
  }
  return { directory: searched[0]!, searched }
}

const AVAILABLE_SCRIPTS: Record<string, { description: string; args: string }> = {
  jwt_tamper: {
    description: "JWT token decode/modify/re-encode for auth bypass testing (alg=none, role escalation, user ID swap)",
    args: "TOKEN [--decode-only] [--set key=value] [--set-header key=value] [--key SECRET] [--json-output]",
  },
  race_tester: {
    description: "Race condition tester — concurrent requests to detect TOCTOU vulnerabilities",
    args: "URL [-m METHOD] [-H key:value] [-d JSON_BODY] [-c COUNT] [--delay MS] [--json-output]",
  },
  ssrf_listener: {
    description: "SSRF callback listener — lightweight HTTP server that logs all incoming requests as evidence",
    args: "[-p PORT] [-o OUTPUT_FILE] [--timeout SECONDS]",
  },
  file_upload_tester: {
    description: "File upload vulnerability tester — extension bypass, MIME bypass, polyglot files, SVG XSS/SSRF",
    args: "URL [--field NAME] [-H key:value] [--data JSON] [--json-output]",
  },
  cloud_storage_enum: {
    description: "Read-only cloud storage enumeration by default; S3 write-probe is explicit opt-in",
    args: "TARGET [--names BUCKET_NAME...] [--check-writes] [--json-output]",
  },
  subdomain_takeover: {
    description: "Subdomain takeover checker — CNAME detection + cloud service fingerprint matching (20 services)",
    args: "FILE_OR_DOMAIN [--json-output]",
  },
  github_dorker: {
    description: "GitHub intelligence dorker — search for leaked secrets using gh CLI (30+ patterns)",
    args: "ORG [--repo ORG/REPO] [--patterns PATTERN...] [--commits] [--json-output]",
  },
  wayback_endpoints: {
    description: "Wayback Machine endpoint discovery — find historical/hidden endpoints via CDX API",
    args: "DOMAIN [--probe] [--limit N] [--json-output]",
  },
}

export const AttackScriptTool = Tool.define("attack_script", {
  description: `Execute one registered bundled Python script for a specialized task beyond http_replay. Available scripts: ${Object.keys(AVAILABLE_SCRIPTS).join(", ")}. Load the community-tool-selection skill and read the TOOLING_CATALOG.md companion using the returned Base directory and skill_files before calling it; never resolve it against the target workspace. The runner enforces persisted target scope for network-capable scripts and requires an explicitly running vulnerability_testing checkpoint for race, upload, takeover, SSRF-listener, and cloud write tests. Supply target_url as the canonical in-scope workspace context for ssrf_listener and github_dorker. Wayback --probe is refused because this script does not apply per-URL scope checks; use scoped request tools instead. Some scripts make state-changing requests or upload active payloads; never use them during default reconnaissance, and never run write/concurrency/upload modes without explicit program authorization. Use --json-output for machine-readable output.`,
  parameters: z.object({
    script: z.enum(Object.keys(AVAILABLE_SCRIPTS) as [string, ...string[]]).describe(
      "Script to execute. Options: " +
        Object.entries(AVAILABLE_SCRIPTS)
          .map(([k, v]) => `${k} — ${v.description}`)
          .join("; "),
    ),
    args: z.array(z.string()).describe("Arguments to pass to the script"),
    target_url: z.string().url().optional().describe("Canonical in-scope target workspace context; required for ssrf_listener and github_dorker"),
    timeout_seconds: z.number().optional().default(120).describe("Maximum execution time in seconds (default: 120)"),
  }),
  async execute(params) {
    const { directory: scriptsDir, searched: scriptDirectoriesSearched } = await resolveScriptsDir()
    const scriptPath = path.join(scriptsDir, `${params.script}.py`)
    const file = Bun.file(scriptPath)
    if (!(await file.exists())) {
      return {
        title: `attack_script: ${params.script}`,
        output: "Script not found: " + params.script + ".py\nSearched script directories:\n" + scriptDirectoriesSearched.map((directory) => "  " + directory).join("\n") + "\n\nAvailable scripts:\n" + Object.entries(AVAILABLE_SCRIPTS)
          .map(([k, v]) => `  ${k}: ${v.description}\n    Usage: ${v.args}`)
          .join("\n"),
        metadata: { script: params.script, exitCode: -1, hasStderr: false },
      }
    }

    const denied = (reason: string, metadata: Record<string, unknown> = {}) => ({
      title: `attack_script: ${params.script} — refused`,
      output: "No script was executed. " + reason,
      metadata: { script: params.script, exitCode: -1, hasStderr: false, blocked: true, ...metadata },
    })
    const normalizeTarget = (value: string): string | undefined => {
      try {
        const url = new URL(value.includes("://") ? value : "https://" + value)
        return url.protocol === "http:" || url.protocol === "https:" ? url.href : undefined
      } catch {
        return undefined
      }
    }
    const normalizeHostTarget = (value: string): string | undefined => {
      try {
        const url = new URL(value.includes("://") ? value : "https://" + value)
        if (url.protocol !== "http:" && url.protocol !== "https:") return undefined
        return "https://" + url.hostname + "/"
      } catch {
        return undefined
      }
    }

    // The offline JWT transformer never sends a request. Every other script
    // must be anchored to a concrete, persisted in-scope target.
    const scriptTargets: string[] = []
    const args = params.args
    const first = args[0]
    if (params.target_url) {
      const target = normalizeTarget(params.target_url)
      if (!target) return denied("target_url must be an HTTP(S) URL.")
      scriptTargets.push(target)
    }

    if (params.script === "race_tester" || params.script === "file_upload_tester") {
      const target = first ? normalizeTarget(first) : undefined
      if (!target) return denied("Provide the exact HTTP(S) target URL as the first script argument.")
      scriptTargets.push(target)
    } else if (params.script === "ssrf_listener" || params.script === "github_dorker") {
      if (!params.target_url) return denied("Provide target_url so this script is anchored to the authorized target workspace.")
    } else if (params.script === "subdomain_takeover") {
      if (!first) return denied("Provide a domain or an in-scope subdomain file.")
      const inputFile = first.includes("://") ? undefined : Bun.file(first)
      const domains = inputFile && await inputFile.exists()
        ? (await inputFile.text()).split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"))
        : [first]
      if (!domains.length) return denied("The supplied subdomain file contains no candidate hosts.")
      for (const domain of domains) {
        const target = normalizeHostTarget(domain)
        if (!target) return denied("Invalid takeover candidate host: " + domain)
        scriptTargets.push(target)
      }
    } else if (params.script === "cloud_storage_enum") {
      if (!first) return denied("Provide a target domain or explicitly named bucket set.")
      const baseTarget = normalizeTarget(first)
      if (!baseTarget) return denied("Cloud storage target must be a valid in-scope domain or URL.")
      scriptTargets.push(baseTarget)
      const namesIndex = args.indexOf("--names")
      const names = namesIndex >= 0
        ? args.slice(namesIndex + 1).filter((item) => !item.startsWith("--"))
        : (() => {
            const base = new URL(baseTarget).hostname.replace(/\./g, "-").replace(/\s/g, "-").toLowerCase()
            return [
              base, `${base}-dev`, `${base}-staging`, `${base}-prod`, `${base}-backup`,
              `${base}-assets`, `${base}-static`, `${base}-media`, `${base}-uploads`,
              `${base}-data`, `${base}-logs`, `${base}-internal`, `${base}-private`,
              `${base}-public`, `${base}-cdn`, `${base}-web`, `${base}-app`,
              `${base}-api`, `${base}-db`, `${base}-config`, `${base}-test`,
              `dev-${base}`, `staging-${base}`, `prod-${base}`, `backup-${base}`,
            ]
          })()
      if (!names.length) return denied("--names requires at least one explicit bucket name.")
      for (const name of names) {
        scriptTargets.push(
          `https://${name}.s3.amazonaws.com/`,
          `https://s3.amazonaws.com/${name}`,
          `https://${name}.blob.core.windows.net/`,
          `https://storage.googleapis.com/${name}`,
        )
        if (args.includes("--check-writes")) {
          scriptTargets.push(
            `https://${name}.s3.amazonaws.com/cyberstrike_test.txt`,
            `https://s3.amazonaws.com/${name}/cyberstrike_test.txt`,
          )
        }
      }
    } else if (params.script === "wayback_endpoints") {
      if (args.includes("--probe")) {
        return denied("Wayback --probe is disabled because the script cannot scope-check every archived URL before sending HEAD requests. Use the scoped HTTP request tools for verified in-scope URLs.")
      }
      const target = first ? normalizeHostTarget(first) : undefined
      if (!target) return denied("Provide the exact in-scope domain as the first script argument.")
      scriptTargets.push(target)
    }

    if (params.script !== "jwt_tamper" && !scriptTargets.length) {
      return denied("This network-capable script requires a concrete in-scope target context.")
    }

    const authorizedWorkspaces = new Map<string, NonNullable<Awaited<ReturnType<typeof TargetMemory.checkURLScope>>["workspace"]>>()
    for (const target of [...new Set(scriptTargets)]) {
      const authorization = await TargetMemory.checkURLScope(target)
      if (!authorization.allowed || !authorization.workspace) {
        return denied("Target is outside persisted scope or has no canonical workspace: " + target, {
          scopeDenied: true,
          reason: authorization.reason ?? "target_out_of_scope",
          target,
        })
      }
      authorizedWorkspaces.set(authorization.workspace.id, authorization.workspace)
    }

    const requiresVulnerabilityTesting =
      params.script === "race_tester" ||
      params.script === "file_upload_tester" ||
      params.script === "ssrf_listener" ||
      params.script === "subdomain_takeover" ||
      (params.script === "cloud_storage_enum" && args.includes("--check-writes"))
    if (requiresVulnerabilityTesting) {
      for (const workspace of authorizedWorkspaces.values()) {
        const gate = await reconPhaseGate(workspace, "vulnerability_testing")
        if (!gate.allowed) {
          return denied("Active testing is blocked until the explicit vulnerability_testing checkpoint is running: " + gate.reason, {
            testingDenied: true,
            manifest: gate.manifestPath,
          })
        }
      }
    }

    const proc = Bun.spawn(["python3", scriptPath, ...params.args], {
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    })

    const timeout = setTimeout(() => {
      proc.kill()
    }, params.timeout_seconds * 1000)

    const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])

    clearTimeout(timeout)
    const exitCode = await proc.exited

    const output = [stdout]
    if (stderr.trim()) output.push(`\n--- stderr ---\n${stderr}`)
    if (exitCode !== 0) output.push(`\nExit code: ${exitCode}`)

    return {
      title: `attack_script: ${params.script}`,
      output: output.join(""),
      metadata: {
        script: params.script,
        exitCode,
        hasStderr: stderr.trim().length > 0,
      },
    }
  },
})
