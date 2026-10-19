import z from "zod"
import { spawn } from "child_process"
import { Tool } from "./tool"
import path from "path"
import fs from "node:fs/promises"
import DESCRIPTION from "./bash.txt"
import { Log } from "../util/log"
import { Instance } from "../project/instance"
import { lazy } from "@/util/lazy"
import { Language } from "web-tree-sitter"

import { $ } from "bun"
import { Filesystem } from "@/util/filesystem"
import { fileURLToPath } from "url"
import { Flag } from "@/flag/flag.ts"
import { Shell } from "@/shell/shell"

import { BashArity } from "@/permission/arity"
import { Truncate } from "./truncation"
import { Plugin } from "@/plugin"
import { TargetMemory, type TargetScope, type Workspace } from "../target"
import { reconPhaseGate, type ReconPhase } from "../target/recon-gate"

const MAX_METADATA_LENGTH = 30_000

// Detect binary content in a buffer by checking for high density of
// non-printable bytes. Printable = ASCII 0x20-0x7E, tab, newline, CR, ESC
// (for ANSI colors). If >30% of bytes are non-printable, treat as binary.
function isBinaryBuffer(buf: Buffer): boolean {
  if (buf.length === 0) return false
  let nonPrintable = 0
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]
    if (b >= 0x20 && b <= 0x7e) continue
    if (b === 0x09 || b === 0x0a || b === 0x0d || b === 0x1b) continue
    if (b >= 0xc0) continue // UTF-8 lead bytes
    if (b >= 0x80 && b <= 0xbf) continue // UTF-8 continuation
    nonPrintable++
  }
  return nonPrintable / buf.length > 0.3
}

const SCANNER_PHASES: Record<string, ReconPhase> = {
  subfinder: "asset_discovery",
  amass: "asset_discovery",
  assetfinder: "asset_discovery",
  sublist3r: "asset_discovery",
  nmap: "live_hosts_ports",
  masscan: "live_hosts_ports",
  naabu: "live_hosts_ports",
  httpx: "live_hosts_ports",
  dnsx: "live_hosts_ports",
  katana: "url_collection",
  gau: "url_collection",
  waybackurls: "url_collection",
  hakrawler: "url_collection",
  gospider: "url_collection",
  paramspider: "parameter_discovery",
  curl: "url_collection",
  wget: "url_collection",
  arjun: "parameter_fuzzing",
  nuclei: "vulnerability_testing",
  ffuf: "directory_fuzzing",
  feroxbuster: "directory_fuzzing",
  gobuster: "directory_fuzzing",
  dirsearch: "directory_fuzzing",
  dirb: "directory_fuzzing",
  nikto: "vulnerability_testing",
  sqlmap: "vulnerability_testing",
  dalfox: "vulnerability_testing",
  wpscan: "vulnerability_testing",
}

function scannerTargets(command: string[], commandText: string): string[] {
  const candidates = new Set<string>()
  for (const match of commandText.matchAll(/https?:\/\/[^\s"'<>\x60]+/gi)) {
    const value = match[0].replace(/[),;]+$/, "")
    candidates.add(value)
  }
  const targetFlags = new Set(["-u", "--url", "-target", "--target", "-host", "--host", "-d", "--domain", "-h"])
  for (let i = 0; i < command.length; i++) {
    if (!targetFlags.has(command[i]!.toLowerCase())) continue
    const value = command[i + 1]
    if (!value || value.startsWith("-")) continue
    if (/^https?:\/\//i.test(value)) candidates.add(value)
    else if (/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s]*)?$/i.test(value)) {
      candidates.add("https://" + value)
    }
  }
  // Nmap-style tools accept hosts as positional arguments.
  for (const value of command) {
    if (value.startsWith("-") || value.includes("/") || value.includes("=") || value.includes(".txt") || value.includes(".list")) continue
    if (/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?$/i.test(value) ||
        /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$/.test(value)) candidates.add("https://" + value)
  }
  return [...candidates]
}

function stripOuterShellQuotes(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2 &&
      ((trimmed.startsWith("'") && trimmed.endsWith("'")) ||
       (trimmed.startsWith('"') && trimmed.endsWith('"')))) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

function hostnameMatchesScopeRule(ruleInput: string, hostname: string): boolean {
  let rule = ruleInput.trim().toLowerCase()
  const typed = rule.match(/^(domain|wildcard)[ \t]*:[ \t]*(.+)$/i)
  if (typed) {
    rule = typed[2]!.trim()
    if (typed[1]!.toLowerCase() === "wildcard" && !rule.includes("*") && !/\{[^{}]+\}/.test(rule)) {
      rule = "*." + rule
    }
  }
  if (/^https?:\/\//i.test(rule) || rule.includes("/") || rule.includes(":")) return false
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(2).replace(/\.$/, "")
    return hostname === suffix || hostname.endsWith("." + suffix)
  }
  return rule.replace(/\.$/, "") === hostname
}

/**
 * Katana can run from the generic shell only when constrained to one FQDN and
 * the persisted manifest grants host-wide access without path/port exclusions.
 * Katana cannot call CyberStrike's scope matcher before every HTTP request, so
 * a narrower manifest must use a scope-aware request/crawl path instead.
 */
export function katanaScopeBlockReason(args: string[], targetURL: string, scopeInput: TargetScope | TargetScope[] | null, workspacePath?: string): string | undefined {
  const scopes = (Array.isArray(scopeInput) ? scopeInput : scopeInput ? [scopeInput] : [])
    .filter((scope) => scope.status === "configured" && scope.scopeItems.length > 0)
  if (scopes.length === 0) {
    return "Katana requires a configured, non-empty persisted scope manifest."
  }

  const normalizedArgs = args.map((arg) => stripOuterShellQuotes(arg).toLowerCase())
  const urlFlagIndexes = normalizedArgs.map((arg, index) => ["-u", "--url"].includes(arg) ? index : -1).filter((index) => index >= 0)
  if (urlFlagIndexes.length === 0) {
    return "Pass an explicit '-u https://authorized-host' input for each authorized host; URL-list/file inputs are not accepted by the generic shell crawler gate."
  }
  for (const index of urlFlagIndexes) {
    const value = args[index + 1] ? stripOuterShellQuotes(args[index + 1]!) : ""
    if (!value || !/^https?:\/\//i.test(value)) {
      return "Every Katana '-u' input must be an explicit absolute HTTP(S) URL, not a filename, wildcard, or unresolved target list."
    }
  }
  if (normalizedArgs.some((arg) => ["-ns", "--no-scope", "-do", "--display-out-scope", "-cs", "--crawl-scope"].includes(arg))) {
    return "Katana scope overrides that can widen crawler behavior are not allowed; rely on the persisted scope and FQDN field scope."
  }
  const fieldScopeIndex = normalizedArgs.findIndex((arg) => ["-fs", "--field-scope"].includes(arg))
  if (fieldScopeIndex < 0 || normalizedArgs[fieldScopeIndex + 1] !== "fqdn") {
    return "Run Katana with '-fs fqdn' so it follows URLs on each explicitly supplied hostname only."
  }

  const rateIndex = normalizedArgs.findIndex((arg) => ["-rl", "--rate-limit"].includes(arg))
  const rate = rateIndex >= 0 ? Number(stripOuterShellQuotes(args[rateIndex + 1] ?? "")) : NaN
  if (!Number.isInteger(rate) || rate < 1 || rate > 10) {
    return "Set Katana's explicit '-rl 5' (allowed range 1-10) to avoid unbounded default request rates."
  }
  const depthIndex = normalizedArgs.findIndex((arg) => ["-d", "--depth"].includes(arg))
  if (depthIndex < 0) {
    return "Set an explicit Katana depth with '-d 3' (allowed range 1-5) so the crawl has a predictable boundary."
  }
  const depth = Number(stripOuterShellQuotes(args[depthIndex + 1] ?? ""))
  if (!Number.isInteger(depth) || depth < 1 || depth > 5) {
    return "Katana depth must be between 1 and 5 for a bounded reconnaissance crawl."
  }

  let target: URL
  try {
    target = new URL(targetURL)
  } catch {
    return "Katana target must be an absolute HTTP(S) URL."
  }
  const hostname = target.hostname.toLowerCase().replace(/\.$/, "")

  // Every configured scope in the asset's ancestry is authoritative. FQDN is
  // insufficient for URL/path/port-only inclusions or any narrower exclusions.
  for (const scope of scopes) {
    const broadInclude = scope.scopeItems.some((item) => hostnameMatchesScopeRule(item, hostname))
    if (!broadInclude) {
      return "Katana requires an exact-host or wildcard-domain scope entry covering " + hostname + " in every applicable scope layer; URL/path/port-only scope needs per-request scope enforcement."
    }

    for (const item of scope.excludedItems) {
      const raw = item.trim().replace(/^(?:url)[ \t]*:[ \t]*/i, "")
      if (/^https?:\/\//i.test(raw)) {
        let excluded: URL
        try { excluded = new URL(raw.replace("*.", "scope-wildcard.")) } catch { continue }
        const excludedHost = excluded.hostname.toLowerCase().replace(/\.$/, "")
        const wildcard = excludedHost.startsWith("scope-wildcard.")
        const wildcardBase = wildcard ? excludedHost.slice("scope-wildcard.".length) : ""
        const hostMatches = excludedHost === hostname ||
          (wildcard && (hostname === wildcardBase || hostname.endsWith("." + wildcardBase)))
        if (hostMatches) {
          return "Katana cannot enforce the saved URL/path/protocol/port exclusion '" + item + "' for " + hostname + "; use the scope-aware crawler."
        }
        continue
      }

      // HackerOne URL exclusions may omit the scheme, e.g. "url: example.com/private".
      // FQDN filtering cannot preserve those narrower request boundaries either.
      if (raw.includes("/")) {
        let excludedURL: URL | undefined
        try { excludedURL = new URL("https://" + raw.replace("*.", "scope-wildcard.")) }
        catch { excludedURL = undefined }
        if (excludedURL && (excludedURL.hostname.toLowerCase() === hostname ||
            hostname.endsWith("." + excludedURL.hostname.toLowerCase().replace(/^scope-wildcard\./, "")))) {
          return "Katana cannot enforce the saved URL/path exclusion '" + item + "' for " + hostname + "; use the scope-aware crawler."
        }
      }

      const hostPort = raw.match(/^([^:/]+):(\d{1,5})$/)
      if (hostPort && hostPort[1]!.toLowerCase().replace(/\.$/, "") === hostname) {
        return "Katana cannot enforce the saved port exclusion '" + item + "' for " + hostname + "; use the scope-aware crawler."
      }

      let exclusion = raw
      const typed = exclusion.match(/^(domain|wildcard)[ \t]*:[ \t]*(.+)$/i)
      if (typed) {
        exclusion = typed[2]!.trim()
        if (typed[1]!.toLowerCase() === "wildcard" && !exclusion.includes("*") && !/\{[^{}]+\}/.test(exclusion)) {
          exclusion = "*." + exclusion
        }
      }
      if (exclusion.startsWith("*.")) {
        const suffix = exclusion.slice(2).replace(/\.$/, "")
        if (hostname === suffix || hostname.endsWith("." + suffix)) {
          return "Katana cannot safely merge the saved host exclusion '" + item + "' into a single-host crawl."
        }
      } else if (exclusion.toLowerCase().replace(/\.$/, "") === hostname) {
        return "Katana cannot safely merge the saved host exclusion '" + item + "' into a single-host crawl."
      }
    }
  }

  const outputFlagIndex = normalizedArgs.findIndex((arg) => ["-o", "-output"].includes(arg))
  if (outputFlagIndex < 0 || !args[outputFlagIndex + 1]) {
    return "Save Katana's raw results with '-o <absolute path under this target workspace/urls/>'; stdout-only crawling cannot complete the URL-collection artifact."
  }
  if (!workspacePath) {
    return "Katana output cannot be validated because the canonical target workspace path is unavailable."
  }
  const outputArg = stripOuterShellQuotes(args[outputFlagIndex + 1]!)
  if (!path.isAbsolute(outputArg)) {
    return "Katana output path must be absolute and remain inside this target workspace's urls/ directory."
  }
  const scansRoot = path.resolve(workspacePath, "urls")
  const outputPath = path.resolve(outputArg)
  const relativeOutput = path.relative(scansRoot, outputPath)
  if (!relativeOutput || relativeOutput.startsWith("..") || path.isAbsolute(relativeOutput)) {
    return "Katana output path must name a file inside " + scansRoot + "; do not write outside the target workspace."
  }

  return undefined
}

async function assertScannerReconGate(command: string[], commandText: string): Promise<void> {
  const scannerIndex = command.findIndex((value) => SCANNER_PHASES[path.basename(value).toLowerCase()] !== undefined)
  if (scannerIndex < 0) {
    // Only inspect shell-wrapper payloads for nested scanner commands. Searching the
    // entire command text causes false positives for ordinary file searches such as
    // find / -iname "*gau*" and for comments/URLs containing tool names.
    const executable = path.basename(command[0] ?? "").toLowerCase()
    const shellWrappers = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"])
    if (shellWrappers.has(executable)) {
      const commandFlag = command.findIndex((value) => value === "-c" || value === "-lc" || value === "-ec")
      const payload = commandFlag >= 0 ? command[commandFlag + 1] ?? "" : ""
      const wrappedScanner = Object.keys(SCANNER_PHASES).find((name) =>
        new RegExp("^\\s*(?:(?:env|sudo)\\s+)*(?:[^\\s;&|]+/)*" + name + "(?:\\s|$)", "i").test(payload.trim()),
      )
      if (wrappedScanner) {
        throw new Error("Recon execution gate blocked an indirect/wrapped " + wrappedScanner + " invocation. Run the scanner as a direct command so target scope and phase prerequisites can be checked.")
      }
    }
    return
  }
  const scanner = path.basename(command[scannerIndex]!).toLowerCase()
  const args = command.slice(scannerIndex + 1)
  if (args.some((value) => ["--help", "-h", "--version", "-version", "-V"].includes(value)) &&
      !args.some((value) => /^https?:\/\//i.test(value))) return
  if (["hakrawler", "gospider"].includes(scanner)) {
    throw new Error("Recon execution gate blocked " + scanner + " in generic shell mode because its crawl cannot consult persisted scope before each request. Use the scope-aware browser/recon pipeline.")
  }
  // These flags identify target-list modes for recon scanners. Do not apply this
  // generic check to curl/wget: curl's case-sensitive -L means "follow redirects",
  // and lowercasing it incorrectly turns it into the blocked "-l" list flag.
  const supportsTargetListGate = !["curl", "wget"].includes(scanner)
  if (supportsTargetListGate && args.some((value) => ["-l", "-list", "--list", "-dl", "-il", "-targets", "--targets-file"].includes(value.toLowerCase()))) {
    throw new Error("Recon execution gate blocked " + scanner + ": target-list input is not accepted until every entry can be individually scope-checked and tied to the current phase manifest.")
  }
  let portScanPorts: number[] | undefined
  if (["nmap", "masscan", "naabu"].includes(scanner)) {
    const portFlag = args.findIndex((value) => ["-p", "--ports", "-port"].includes(value.toLowerCase()))
    const portSpec = portFlag >= 0 ? args[portFlag + 1] : undefined
    if (!portSpec || !/^\d+(?:,\d+)*$/.test(portSpec)) {
      throw new Error("Recon execution gate blocked " + scanner + ": an explicit comma-separated port list is required; ranges, all-port defaults, and unbounded scans are not allowed by this gate.")
    }
    portScanPorts = [...new Set(portSpec.split(",").map(Number))]
    if (!portScanPorts.length || portScanPorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
      throw new Error("Recon execution gate blocked " + scanner + ": port list must contain valid ports from 1 to 65535.")
    }
  }
  let phase = SCANNER_PHASES[scanner]!
  // Route ffuf into the correct recon checkpoint based on its URL placeholder.
  // Body/mutating ffuf requests remain active testing, not discovery.
  if (scanner === "ffuf") {
    const urlIndex = args.findIndex((value) => ["-u", "--url"].includes(value.toLowerCase()))
    const url = urlIndex >= 0 ? args[urlIndex + 1] ?? "" : ""
    const methodIndex = args.findIndex((value) => ["-x", "--request"].includes(value.toLowerCase()))
    const explicitMethod = methodIndex >= 0 ? args[methodIndex + 1]?.toUpperCase() : undefined
    const hasBody = args.some((value) => ["-d", "--data", "--data-raw", "--data-binary", "-F", "--form"].includes(value))
    if (hasBody || (explicitMethod && !["GET", "HEAD"].includes(explicitMethod))) phase = "vulnerability_testing"
    else if (url.includes("?") && /FUZZ/i.test(url.slice(url.indexOf("?")))) phase = "parameter_fuzzing"
    else phase = "directory_fuzzing"
  }
  // Plain retrieval belongs to URL collection; mutating/non-safe HTTP methods
  // are active vulnerability testing and must wait for the final inventory gate.
  if (scanner === "curl") {
    const methodIndex = args.findIndex((value) => ["-x", "--request"].includes(value.toLowerCase()))
    const explicitMethod = methodIndex >= 0 ? args[methodIndex + 1]?.toUpperCase() : undefined
    const hasBody = args.some((value) => ["-d", "--data", "--data-raw", "--data-binary", "-F", "--form"].includes(value))
    if (hasBody || (explicitMethod && !["GET", "HEAD"].includes(explicitMethod))) phase = "vulnerability_testing"
  }
  let targets = scannerTargets(command.slice(scannerIndex), commandText)

  // Passive Wayback CDX lookups are requests to a research provider, not scans of
  // that provider. Authorize the domain being queried against the persisted target
  // scope and URL-collection checkpoint, while only allowing the read-only CDX API.
  if (["curl", "wget"].includes(scanner) && targets.length === 1) {
    const requestURL = new URL(targets[0]!)
    if (requestURL.hostname === "web.archive.org" && requestURL.pathname === "/cdx/search/cdx") {
      const methodIndex = args.findIndex((value) => ["-x", "--request", "--method"].includes(value.toLowerCase()))
      const explicitMethod = methodIndex >= 0 ? args[methodIndex + 1]?.toUpperCase() : undefined
      const hasBody = args.some((value) => ["-d", "--data", "--data-raw", "--data-binary", "-F", "--form", "--post-data", "--post-file"].includes(value))
      if (hasBody || (explicitMethod && !["GET", "HEAD"].includes(explicitMethod))) {
        throw new Error("Recon execution gate blocked archive lookup: only read-only GET/HEAD CDX requests are permitted.")
      }
      const archivedPattern = requestURL.searchParams.get("url")
      const domain = archivedPattern?.replace(/^\\*\\./, "").split(/[/*?]/, 1)[0]?.toLowerCase()
      if (!domain || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$/.test(domain)) {
        throw new Error("Recon execution gate blocked archive lookup: CDX query must identify a concrete target domain.")
      }
      targets = ["https://" + domain + "/"]
    }
  }
  if (!targets.length) {
    throw new Error("Recon execution gate blocked " + scanner + ": pass explicit target URL/host(s). Target-list/file mode is blocked until each target can be checked against persisted scope and phase checkpoints.")
  }
  const workspaceScopes = new Map<string, Promise<TargetScope[]>>()
  const scopesForWorkspace = (start: Workspace): Promise<TargetScope[]> => {
    const cached = workspaceScopes.get(start.id)
    if (cached) return cached
    const pending = (async () => {
      const allWorkspaces = new Map(TargetMemory.list().map((item) => [item.id, item]))
      const scopes: TargetScope[] = []
      const visited = new Set<string>()
      let current: Workspace | undefined = start
      while (current) {
        if (visited.has(current.id)) throw new Error("target workspace ancestry contains a cycle")
        visited.add(current.id)
        const currentScope = await TargetMemory.getScope(current.targetURL)
        if (currentScope?.status === "configured") scopes.push(currentScope)
        if (!current.parentTargetID) break
        current = allWorkspaces.get(current.parentTargetID)
        if (!current) throw new Error("parent target workspace is missing; refusing to weaken inherited scope")
      }
      return scopes
    })()
    workspaceScopes.set(start.id, pending)
    return pending
  }

  for (const target of targets) {
    let url: string
    try {
      const parsed = new URL(target)
      if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password) throw new Error("unsupported URL")
      url = parsed.toString()
    } catch {
      throw new Error("Recon execution gate blocked " + scanner + ": could not normalize target " + target)
    }
    const targetURLs = portScanPorts
      ? portScanPorts.map((port) => {
          const portProtocol = port === 80 ? "http:" : port === 443 ? "https:" : new URL(url).protocol
          const target = new URL(url)
          target.protocol = portProtocol
          target.port = String(port)
          target.pathname = "/"
          target.search = ""
          target.hash = ""
          return target.toString()
        })
      : [url]
    for (const scopedURL of targetURLs) {
      const decision = await TargetMemory.checkURLScope(scopedURL)
      if (!decision.allowed || !decision.workspace) {
        throw new Error("Recon execution gate blocked " + scanner + " for " + scopedURL + ": persisted scope rejected the target/port (" + decision.reason + "). No scanner command was started.")
      }
      if (scanner === "katana") {
        let scopes: TargetScope[]
        try {
          scopes = await scopesForWorkspace(decision.workspace)
        } catch (error) {
          throw new Error("Recon execution gate blocked katana for " + scopedURL + ": unable to verify all inherited scope layers (" + (error instanceof Error ? error.message : String(error)) + "). No crawler command was started.")
        }
        const reason = katanaScopeBlockReason(args, scopedURL, scopes, decision.workspace.workspacePath)
        if (reason) {
          throw new Error("Recon execution gate blocked katana for " + scopedURL + ": " + reason + " Use one explicit -u URL per authorized host, -fs fqdn, -rl 5, -d 3, and a unique absolute -o path under that workspace's urls/ directory. No crawler command was started.")
        }
        const outputFlagIndex = args.findIndex((arg) => ["-o", "-output"].includes(stripOuterShellQuotes(arg).toLowerCase()))
        const outputPath = path.resolve(stripOuterShellQuotes(args[outputFlagIndex + 1]!))
        try {
          await fs.lstat(outputPath)
          throw new Error("output file already exists")
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw new Error("Recon execution gate blocked katana because its output path already exists or cannot be checked: " + outputPath + ". Choose a new run-specific path. No crawler command was started.")
          }
        }
      }
      const gate = await reconPhaseGate(decision.workspace, phase)
      if (!gate.allowed) {
        throw new Error("Recon execution gate blocked " + scanner + " for " + scopedURL + ": " + gate.reason + " Checkpoint: " + gate.manifestPath + ". No scanner command was started.")
      }
    }
  }
}

const DEFAULT_TIMEOUT = Flag.CYBERSTRIKE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS || 2 * 60 * 1000

export const log = Log.create({ service: "bash-tool" })

const resolveWasm = (asset: string) => {
  if (asset.startsWith("file://")) return fileURLToPath(asset)
  if (asset.startsWith("/") || /^[a-z]:/i.test(asset)) return asset
  const url = new URL(asset, import.meta.url)
  return fileURLToPath(url)
}

const parser = lazy(async () => {
  const { Parser } = await import("web-tree-sitter")
  const { default: treeWasm } = await import("web-tree-sitter/tree-sitter.wasm" as string, {
    with: { type: "wasm" },
  })
  const treePath = resolveWasm(treeWasm)
  await Parser.init({
    locateFile() {
      return treePath
    },
  })
  const { default: bashWasm } = await import("tree-sitter-bash/tree-sitter-bash.wasm" as string, {
    with: { type: "wasm" },
  })
  const bashPath = resolveWasm(bashWasm)
  const bashLanguage = await Language.load(bashPath)
  const p = new Parser()
  p.setLanguage(bashLanguage)
  return p
})

// TODO: we may wanna rename this tool so it works better on other shells
export const BashTool = Tool.define("bash", async () => {
  const shell = Shell.acceptable()
  log.info("bash tool using shell", { shell })

  return {
    description: DESCRIPTION.replaceAll("${directory}", Instance.directory)
      .replaceAll("${maxLines}", String(Truncate.MAX_LINES))
      .replaceAll("${maxBytes}", String(Truncate.MAX_BYTES)),
    parameters: z.object({
      command: z.string().describe("The command to execute"),
      timeout: z.number().describe("Optional timeout in milliseconds").optional(),
      workdir: z
        .string()
        .describe(
          `The working directory to run the command in. Defaults to ${Instance.directory}. Use this instead of 'cd' commands.`,
        )
        .optional(),
      description: z
        .string()
        .describe(
          "Clear, concise description of what this command does in 5-10 words. Examples:\nInput: ls\nOutput: Lists files in current directory\n\nInput: git status\nOutput: Shows working tree status\n\nInput: npm install\nOutput: Installs package dependencies\n\nInput: mkdir foo\nOutput: Creates directory 'foo'",
        ),
    }),
    async execute(params, ctx) {
      const cwd = params.workdir || Instance.directory
      if (params.timeout !== undefined && params.timeout < 0) {
        throw new Error(`Invalid timeout value: ${params.timeout}. Timeout must be a positive number.`)
      }
      const timeout = params.timeout ?? DEFAULT_TIMEOUT
      const tree = await parser().then((p) => p.parse(params.command))
      if (!tree) {
        throw new Error("Failed to parse command")
      }
      const directories = new Set<string>()
      if (!Instance.containsPath(cwd)) directories.add(cwd)
      const patterns = new Set<string>()
      const always = new Set<string>()

      for (const node of tree.rootNode.descendantsOfType("command")) {
        if (!node) continue

        // Get full command text including redirects if present
        let commandText = node.parent?.type === "redirected_statement" ? node.parent.text : node.text

        const command = []
        for (let i = 0; i < node.childCount; i++) {
          const child = node.child(i)
          if (!child) continue
          if (
            child.type !== "command_name" &&
            child.type !== "word" &&
            child.type !== "string" &&
            child.type !== "raw_string" &&
            child.type !== "concatenation"
          ) {
            continue
          }
          command.push(child.text)
        }

        // Enforce target scope + durable phase gates before known recon/scanner binaries start.
        await assertScannerReconGate(command, commandText)

        // not an exhaustive list, but covers most common cases
        if (["cd", "rm", "cp", "mv", "mkdir", "touch", "chmod", "chown", "cat"].includes(command[0])) {
          for (const arg of command.slice(1)) {
            if (arg.startsWith("-") || (command[0] === "chmod" && arg.startsWith("+"))) continue
            const resolved = await $`realpath ${arg}`
              .cwd(cwd)
              .quiet()
              .nothrow()
              .text()
              .then((x) => x.trim())
            log.info("resolved path", { arg, resolved })
            if (resolved) {
              // Git Bash on Windows returns Unix-style paths like /c/Users/...
              const normalized =
                process.platform === "win32" && resolved.match(/^\/[a-z]\//)
                  ? resolved.replace(/^\/([a-z])\//, (_, drive) => `${drive.toUpperCase()}:\\`).replace(/\//g, "\\")
                  : resolved
              if (!Instance.containsPath(normalized)) {
                const dir = (await Filesystem.isDir(normalized)) ? normalized : path.dirname(normalized)
                directories.add(dir)
              }
            }
          }
        }

        // cd covered by above check
        if (command.length && command[0] !== "cd") {
          patterns.add(commandText)
          always.add(BashArity.prefix(command).join(" ") + " *")
        }
      }

      if (directories.size > 0) {
        const globs = Array.from(directories).map((dir) => path.join(dir, "*"))
        await ctx.ask({
          permission: "external_directory",
          patterns: globs,
          always: globs,
          metadata: {},
        })
      }

      if (patterns.size > 0) {
        await ctx.ask({
          permission: "bash",
          patterns: Array.from(patterns),
          always: Array.from(always),
          metadata: {},
        })
      }

      const shellEnv = await Plugin.trigger("shell.env", { cwd }, { env: {} })
      const proc = spawn(params.command, {
        shell,
        cwd,
        env: {
          ...process.env,
          ...shellEnv.env,
        },
        stdio: ["ignore", "pipe", "pipe"],
        detached: process.platform !== "win32",
      })

      let output = ""

      // Initialize metadata with empty output
      ctx.metadata({
        metadata: {
          output: "",
          description: params.description,
        },
      })

      let binaryDetected = false
      const append = (chunk: Buffer) => {
        if (isBinaryBuffer(chunk)) {
          if (!binaryDetected) {
            binaryDetected = true
            output += "\n[binary output detected and stripped — " + chunk.length + " bytes]\n"
          }
          return
        }
        output += chunk.toString()
        ctx.metadata({
          metadata: {
            // truncate the metadata to avoid GIANT blobs of data (has nothing to do w/ what agent can access)
            output: output.length > MAX_METADATA_LENGTH ? output.slice(0, MAX_METADATA_LENGTH) + "\n\n..." : output,
            description: params.description,
          },
        })
      }

      proc.stdout?.on("data", append)
      proc.stderr?.on("data", append)

      let timedOut = false
      let aborted = false
      let exited = false

      const kill = () => Shell.killTree(proc, { exited: () => exited })

      if (ctx.abort.aborted) {
        aborted = true
        await kill()
      }

      const abortHandler = () => {
        aborted = true
        void kill()
      }

      ctx.abort.addEventListener("abort", abortHandler, { once: true })

      const timeoutTimer = setTimeout(() => {
        timedOut = true
        void kill()
      }, timeout + 100)

      await new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          clearTimeout(timeoutTimer)
          ctx.abort.removeEventListener("abort", abortHandler)
        }

        proc.once("exit", () => {
          exited = true
          cleanup()
          resolve()
        })

        proc.once("error", (error) => {
          exited = true
          cleanup()
          reject(error)
        })
      })

      const resultMetadata: string[] = []

      if (timedOut) {
        resultMetadata.push(`bash tool terminated command after exceeding timeout ${timeout} ms`)
      }

      if (aborted) {
        resultMetadata.push("User aborted the command")
      }

      if (resultMetadata.length > 0) {
        output += "\n\n<bash_metadata>\n" + resultMetadata.join("\n") + "\n</bash_metadata>"
      }

      return {
        title: params.description,
        metadata: {
          output: output.length > MAX_METADATA_LENGTH ? output.slice(0, MAX_METADATA_LENGTH) + "\n\n..." : output,
          exit: proc.exitCode,
          description: params.description,
        },
        output,
      }
    },
  }
})
