import z from "zod"
import { Tool } from "./tool"
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
  description: `Execute one registered bundled Python script for a specialized task beyond http_replay. Available scripts: ${Object.keys(AVAILABLE_SCRIPTS).join(", ")}. Consult .cyberstrike/skill/TOOLING_CATALOG.md for script input, phase, and impact rules before calling it. This runner does not apply the generic Bash target/scope gate: independently verify persisted scope and phase before any network operation. Some scripts make state-changing requests or upload active payloads; never use them during default reconnaissance, and never run write/concurrency/upload modes without explicit program authorization. Use --json-output for machine-readable output.`,
  parameters: z.object({
    script: z.enum(Object.keys(AVAILABLE_SCRIPTS) as [string, ...string[]]).describe(
      "Script to execute. Options: " +
        Object.entries(AVAILABLE_SCRIPTS)
          .map(([k, v]) => `${k} — ${v.description}`)
          .join("; "),
    ),
    args: z.array(z.string()).describe("Arguments to pass to the script"),
    timeout_seconds: z.number().optional().default(120).describe("Maximum execution time in seconds (default: 120)"),
  }),
  async execute(params) {
    const { directory: scriptsDir, searched: scriptDirectoriesSearched } = await resolveScriptsDir()
    const scriptPath = path.join(scriptsDir, `${params.script}.py`)
    const file = Bun.file(scriptPath)
    if (!(await file.exists())) {
      return {
        title: `attack_script: ${params.script}`,
        output: `Script not found: ${params.script}.py\n\nAvailable scripts:\n${Object.entries(AVAILABLE_SCRIPTS)
          .map(([k, v]) => `  ${k}: ${v.description}\n    Usage: ${v.args}`)
          .join("\n")}`,
        metadata: { script: params.script, exitCode: -1, hasStderr: false },
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
