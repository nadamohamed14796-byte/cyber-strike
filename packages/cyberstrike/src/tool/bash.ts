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

/**
 * Nominal task classification used to identify agent-executable scanner commands.
 * Values are advisory routing hints, not a per-checkpoint tool allowlist; the
 * active recon checkpoint and persisted scope are enforced separately below.
 */
const SCANNER_NOMINAL_PHASES: Record<string, ReconPhase> = {
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
  x8: "parameter_fuzzing",
  nuclei: "vulnerability_testing",
  commix: "vulnerability_testing",
  ssrfmap: "vulnerability_testing",
  nosqlmap: "vulnerability_testing",
  crlfuzz: "vulnerability_testing",
  "git-dumper": "vulnerability_testing",
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
function commandExecutableIndex(command: string[]): number {
  const optionWithValue: Record<string, Set<string>> = {
    sudo: new Set(["-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from", "-D", "--chdir", "-R", "--chroot", "-r", "--role", "-t", "--type", "-T", "--command-timeout", "-U", "--other-user"]),
    env: new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]),
    nice: new Set(["-n", "--adjustment"]),
    timeout: new Set(["-k", "--kill-after", "-s", "--signal"]),
    stdbuf: new Set(),
    command: new Set(["-a"]),
    exec: new Set(["-a"]),
  }
  const launchers = new Set(["sudo", "env", "nice", "timeout", "stdbuf", "command", "exec"])
  let index = 0

  while (index < command.length) {
    const token = stripOuterShellQuotes(command[index]!)
    const executable = path.basename(token).toLowerCase()
    if (!launchers.has(executable)) return index
    index++

    const needsValue = optionWithValue[executable] ?? new Set<string>()
    if (executable === "env") {
      while (index < command.length) {
        const arg = stripOuterShellQuotes(command[index]!)
        if (arg === "--") { index++; break }
        if (needsValue.has(arg)) {
          // env -S/--split-string embeds a new command string; leave env as the
          // executable so scannerLaunchedByWrapper can parse that payload as shell.
          if (["-S", "--split-string"].includes(arg)) return index - 1
          index += 2
          continue
        }
        if (arg.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) { index++; continue }
        break
      }
      continue
    }

    if (executable === "timeout") {
      while (index < command.length) {
        const arg = stripOuterShellQuotes(command[index]!)
        if (arg === "--") { index++; break }
        if (!arg.startsWith("-")) break
        index++
        if (needsValue.has(arg)) index++
      }
      // timeout's first positional argument is its duration, not the executable.
      if (index < command.length) index++
      continue
    }

    while (index < command.length) {
      const arg = stripOuterShellQuotes(command[index]!)
      if (arg === "--") { index++; break }
      if (!arg.startsWith("-")) break
      index++
      if (needsValue.has(arg) && !arg.includes("=")) index++
    }
  }
  return -1
}

function scannerExecutableIndex(command: string[]): number {
  const executableIndex = commandExecutableIndex(command)
  if (executableIndex < 0) return -1
  const executable = path.basename(stripOuterShellQuotes(command[executableIndex]!)).toLowerCase()
  return SCANNER_NOMINAL_PHASES[executable] === undefined ? -1 : executableIndex
}

const SCANNER_OUTPUT_FLAGS = new Set(["-o", "--output", "-output", "--output-file", "-out"])

/**
 * Identity for a direct scanner invocation, ignoring only the output destination.
 * Used to catch duplicate scans inside one shell call before any of them run.
 */
export function reconScannerInvocationKey(command: string[]): string | undefined {
  const scannerIndex = scannerExecutableIndex(command)
  if (scannerIndex < 0) return undefined
  const executable = path.basename(stripOuterShellQuotes(command[scannerIndex]!)).toLowerCase()
  const normalizedArgs: string[] = []
  for (let i = scannerIndex + 1; i < command.length; i++) {
    const argument = stripOuterShellQuotes(command[i]!)
    const lower = argument.toLowerCase()
    if (SCANNER_OUTPUT_FLAGS.has(lower)) {
      i++ // Ignore only the output path; source, target and scan options remain part of identity.
      continue
    }
    if (lower.startsWith("--output=")) continue
    normalizedArgs.push(argument)
  }
  return JSON.stringify([command.slice(0, scannerIndex).map(stripOuterShellQuotes), executable, ...normalizedArgs])
}

export function scannerTargets(command: string[], commandText: string): string[] {
  const candidates = new Set<string>()
  const scannerName = path.basename(stripOuterShellQuotes(command[0] ?? "")).toLowerCase()
  // waybackurls consumes stdin; an arbitrary URL elsewhere in the pipeline is
  // not proof that it is the hostname actually fed to the collector.
  if (scannerName !== "waybackurls") {
    for (const match of commandText.matchAll(/https?:\/\/[^\s"'<>\x60]+/gi)) {
      const value = match[0].replace(/[),;]+$/, "")
      candidates.add(value)
    }
  }
  const targetFlags = new Set(["-u", "--url", "-target", "--target", "-host", "--host", "-d", "--domain", "-h"])
  const addTargetValue = (rawValue: string, allowDomainList: boolean) => {
    const value = stripOuterShellQuotes(rawValue).trim()
    if (!value || value.startsWith("-")) return
    // Subdomain enumerators commonly accept comma-separated roots and inline
    // domain flags. Authorize each root separately rather than treating the
    // entire list as one invalid hostname or blocking the tool unnecessarily.
    const values = allowDomainList ? value.split(",").map((item) => item.trim()).filter(Boolean) : [value]
    for (let candidate of values) {
      if (!candidate) continue
      if (/^https?:\/\//i.test(candidate)) {
        candidates.add(candidate)
        continue
      }
      // A wildcard in the saved program scope means enumerate its DNS root;
      // the runtime still checks that concrete root against the persisted scope.
      candidate = candidate.replace(/^\*\./, "")
      if (/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s]*)?$/i.test(candidate)) {
        candidates.add("https://" + candidate)
      } else if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$/.test(candidate)) {
        candidates.add("https://" + candidate)
      }
    }
  }
  const allowDomainList = ["subfinder", "amass", "assetfinder", "sublist3r"].includes(scannerName)
  for (let i = 0; i < command.length; i++) {
    const flag = stripOuterShellQuotes(command[i]!).toLowerCase()
    if (targetFlags.has(flag)) {
      const value = command[i + 1]
      if (!value) continue
      addTargetValue(value, allowDomainList && ["-d", "--domain"].includes(flag))
      continue
    }
    const inline = flag.match(/^(-u|--url|-target|--target|-host|--host|-d|--domain|-h)=(.+)$/)
    if (inline) addTargetValue(inline[2]!, allowDomainList && ["-d", "--domain"].includes(inline[1]!))
  }
  // waybackurls consumes hosts on stdin instead of argv. Permit only literal
  // hostnames from its immediately enclosing pipeline; every extracted host
  // still passes the same persisted scope check before the source request starts.
  if (path.basename(stripOuterShellQuotes(command[0] ?? "")).toLowerCase() === "waybackurls") {
    const pipelineIndex = commandText.lastIndexOf("|")
    const inputText = pipelineIndex >= 0 ? commandText.slice(0, pipelineIndex) : ""
    const hostPattern = /(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/gi
    const literalProducer = /^\s*(?:printf|echo)\b/i.test(inputText)
    if (literalProducer) {
      for (const match of inputText.matchAll(hostPattern)) {
        const hostname = match[0].toLowerCase().replace(/\.$/, "")
        // Avoid treating filenames (e.g. domains.txt or hosts.json) as authorized hosts.
        if (/\.(?:txt|list|csv|json|jsonl|xml|yaml|yml|log|md|html|js|map|pdf)$/i.test(hostname)) continue
        if (hostname.includes("waybackurls")) continue
        candidates.add("https://" + hostname)
      }
    }
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
  const optionGroups = [
    ["-u", "--url"],
    ["-fs", "--field-scope"],
    ["-rl", "--rate-limit"],
    ["-d", "--depth"],
    ["-o", "-output"],
  ]
  for (const group of optionGroups) {
    if (normalizedArgs.filter((arg) => group.includes(arg)).length > 1) {
      return "Use each Katana scope/rate/depth/output option once per command. Duplicate flags can make the crawler's effective settings differ from the values checked by the gate."
    }
  }
  const urlFlagIndexes = normalizedArgs.map((arg, index) => ["-u", "--url"].includes(arg) ? index : -1).filter((index) => index >= 0)
  if (urlFlagIndexes.length === 0) {
    return "Pass an explicit '-u https://authorized-host' input for each authorized host; URL-list/file inputs are not accepted by the generic shell crawler gate."
  }
  const inputURLs: URL[] = []
  for (const index of urlFlagIndexes) {
    const value = args[index + 1] ? stripOuterShellQuotes(args[index + 1]!) : ""
    if (!value || !/^https?:\/\//i.test(value)) {
      return "Every Katana '-u' input must be an explicit absolute HTTP(S) URL, not a filename, wildcard, or unresolved target list."
    }
    try {
      const parsed = new URL(value)
      if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password) {
        return "Every Katana '-u' input must be a credential-free HTTP(S) URL."
      }
      inputURLs.push(parsed)
    } catch {
      return "Every Katana '-u' input must be a valid absolute HTTP(S) URL."
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
    return "Set an explicit Katana depth (for example '-d 3'); increase it when the observed application has deeper eligible paths. There is no hard-coded maximum depth."
  }
  const depth = Number(stripOuterShellQuotes(args[depthIndex + 1] ?? ""))
  if (!Number.isSafeInteger(depth) || depth < 1) {
    return "Katana depth must be a positive safe integer. Choose enough depth for the target; do not treat the example depth as a discovery cap."
  }
  if (!normalizedArgs.some((arg) => ["-j", "-json", "-jsonl"].includes(arg))) {
    return "Use Katana JSONL output ('-j') so URL source and request metadata remain available for deduplication and triage."
  }
  if (!normalizedArgs.some((arg) => ["-ncb", "-no-clobber"].includes(arg))) {
    return "Use the no-clobber flag '-ncb' to prevent a concurrent or retried crawl from overwriting an existing evidence artifact."
  }

  let target: URL
  try {
    target = new URL(targetURL)
  } catch {
    return "Katana target must be an absolute HTTP(S) URL."
  }
  const hostname = target.hostname.toLowerCase().replace(/\.$/, "")
  if (!inputURLs.some((input) => input.origin === target.origin)) {
    return "The target checked against persisted scope must match one of this Katana command's explicit '-u' origins."
  }

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
        if (excludedURL) {
          const rawUsesWildcard = raw.includes("*.")
          const exclusionHost = excludedURL.hostname.toLowerCase().replace(/^scope-wildcard\./, "")
          const candidateMatches = rawUsesWildcard
            ? hostname === exclusionHost || hostname.endsWith("." + exclusionHost)
            : hostname === excludedURL.hostname.toLowerCase()
          if (candidateMatches) {
            return "Katana cannot enforce the saved URL/path exclusion '" + item + "' for " + hostname + "; use the scope-aware crawler."
          }
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
  const urlsRoot = path.resolve(workspacePath, "urls")
  const outputPath = path.resolve(outputArg)
  const relativeOutput = path.relative(urlsRoot, outputPath)
  if (!relativeOutput || relativeOutput === ".." || relativeOutput.startsWith(".." + path.sep) || path.isAbsolute(relativeOutput)) {
    return "Katana output path must name a file inside " + urlsRoot + "; do not write outside the target workspace."
  }
  if (path.dirname(outputPath) !== urlsRoot) {
    return "Katana raw output must be a direct child of " + urlsRoot + "; nested output folders are not accepted."
  }
  if (!outputPath.toLowerCase().endsWith(".jsonl")) {
    return "Katana JSON output must use a '.jsonl' extension so later endpoint normalization can parse it deterministically."
  }

  return undefined
}

export async function scannerLaunchedByWrapper(command: string[], executableIndex: number): Promise<string | undefined> {
  const executable = path.basename(stripOuterShellQuotes(command[executableIndex] ?? "")).toLowerCase()
  const scannerName = (value: string | undefined) => {
    if (!value) return undefined
    const name = path.basename(stripOuterShellQuotes(value)).toLowerCase()
    return SCANNER_NOMINAL_PHASES[name] === undefined ? undefined : name
  }
  const shellPayload = async (argv: string[], start: number) => {
    const wrapperName = path.basename(stripOuterShellQuotes(argv[start] ?? "")).toLowerCase()
    if (!SHELL_WRAPPERS.has(wrapperName)) return undefined
    const flag = argv.findIndex((arg, index) => index > start && ["-c", "-lc", "-ec"].includes(stripOuterShellQuotes(arg)))
    if (flag < 0) return undefined
    return findWrappedScanner(stripOuterShellQuotes(argv[flag + 1] ?? ""))
  }
  const inspectNestedInvocation = async (argv: string[]): Promise<string | undefined> => {
    const nestedScannerIndex = scannerExecutableIndex(argv)
    if (nestedScannerIndex >= 0) return scannerName(argv[nestedScannerIndex])
    const nestedExecutableIndex = commandExecutableIndex(argv)
    if (nestedExecutableIndex < 0) return undefined
    const nestedExecutable = path.basename(stripOuterShellQuotes(argv[nestedExecutableIndex]!)).toLowerCase()
    if (["xargs", "parallel", "find", "env"].includes(nestedExecutable)) {
      return scannerLaunchedByWrapper(argv, nestedExecutableIndex)
    }
    if (SHELL_WRAPPERS.has(nestedExecutable)) return shellPayload(argv, nestedExecutableIndex)
    return undefined
  }

  if (executable === "xargs" || executable === "parallel") {
    const withValue = executable === "xargs"
      ? new Set(["-E", "--eof", "-e", "-I", "--replace", "-i", "-L", "--max-lines", "-l", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars", "-d", "--delimiter", "-a", "--arg-file"])
      : new Set(["-j", "--jobs", "-S", "--sshlogin", "-I", "--replace", "-N", "--max-args", "-n", "--max-args", "-a", "--arg-file", "-d", "--delimiter"])
    let index = executableIndex + 1
    while (index < command.length) {
      const arg = stripOuterShellQuotes(command[index]!)
      if (arg === "--") { index++; break }
      if (!arg.startsWith("-")) break
      index++
      if (withValue.has(arg)) index++
    }
    const candidate = command[index]
    return candidate ? inspectNestedInvocation(command.slice(index)) : undefined
  }

  if (executable === "find") {
    for (let index = executableIndex + 1; index < command.length; index++) {
      if (!["-exec", "-execdir"].includes(stripOuterShellQuotes(command[index]!))) continue
      const end = command.findIndex((value, i) => i > index + 1 && [";", "+"].includes(stripOuterShellQuotes(value)))
      const endIndex = end >= 0 ? end : command.length
      const candidateCommand = command.slice(index + 1, endIndex)
      const wrapped = await inspectNestedInvocation(candidateCommand)
      if (wrapped) return wrapped
    }
  }

  if (executable === "env") {
    for (let index = executableIndex + 1; index < command.length; index++) {
      const arg = stripOuterShellQuotes(command[index]!)
      if (["-S", "--split-string"].includes(arg)) {
        const wrapped = await findWrappedScanner(stripOuterShellQuotes(command[index + 1] ?? ""))
        if (wrapped) return wrapped
        continue
      }
      if (arg.startsWith("-")) {
        if (["-u", "--unset", "-C", "--chdir"].includes(arg)) index++
        continue
      }
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) continue
      return inspectNestedInvocation(command.slice(index))
    }
  }
  return undefined
}

/**
 * Resolve a public passive-research API request to the in-scope subject it queries.
 * This is not a tool allowlist: the provider can be any external host, but the
 * lookup must be read-only, credential-free, have one clear domain query, and then
 * pass the persisted scope check for that domain. Known provider routes also set
 * the appropriate recon phase; generic domain lookups default to asset discovery.
 */
export function passiveResearchLookup(
  requestURL: URL,
  args: string[],
): { targetURL: string; phase: ReconPhase } | undefined {
  if (requestURL.username || requestURL.password) return undefined
  // curl normally reads a per-user config file; -q/--disable must be first.
  if (args[0] !== "-q" && args[0] !== "--disable") return undefined

  // curl's method flag is case-sensitive: -X sets the method, while -x selects a proxy.
  if (args.some((item) => item === "-x" || item.startsWith("-x") && item.length > 2)) return undefined
  const methodIndex = args.findIndex((item) =>
    item === "-X" || ["--request", "--method"].includes(item.toLowerCase()),
  )
  const inlineMethod = args.find((item) => /^-X(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)$/i.test(item))
    ?? args.find((item) => /^(?:--request|--method)=/i.test(item))
  const method = methodIndex >= 0
    ? args[methodIndex + 1]
    : inlineMethod?.replace(/^(?:--request|--method)=/i, "").replace(/^-X/i, "")
  const effectiveMethod = method?.toUpperCase()
  if (effectiveMethod && !["GET", "HEAD"].includes(effectiveMethod)) return undefined

  const longBodyAuthOrRouteFlags = new Set([
    "--data", "--data-raw", "--data-urlencode", "--data-binary", "--json",
    "--form", "--form-string", "--post-data", "--post-file",
    "--location", "--location-trusted",
    "--user", "--proxy-user", "--proxy", "--preproxy", "--proxy-header",
    "--cookie", "--cookie-jar", "--netrc", "--netrc-file",
    "--oauth2-bearer", "--aws-sigv4", "--config", "--resolve", "--connect-to",
    "--unix-socket", "--abstract-unix-socket", "--interface", "--insecure",
  ])
  if (args.some((item) => {
    const lower = item.toLowerCase()
    return ["-d", "-F", "-u", "-b", "-L", "-K", "-k"].includes(item) ||
      /^-[^-]*[dFubLKk]/.test(item) ||
      [...longBodyAuthOrRouteFlags].some((flag) => lower === flag || lower.startsWith(flag + "="))
  })) return undefined

  for (let i = 0; i < args.length; i++) {
    const item = args[i]!
    const header = item === "-H" || item.toLowerCase() === "--header"
      ? args[i + 1]
      : item.toLowerCase().startsWith("--header=")
        ? item.slice(item.indexOf("=") + 1)
        : item.startsWith("-H") && item.length > 2
          ? item.slice(2)
          : undefined
    if (header) {
      const name = header.split(":", 1)[0]!.trim()
      const normalizedName = name.toLowerCase()
      const nameTokens = normalizedName.replaceAll("-", "_").split("_").filter(Boolean)
      const hasSensitiveName = [
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "token", "secret", "credential", "password", "signature",
      ].some((token) => normalizedName.includes(token)) ||
        nameTokens.includes("auth") ||
        normalizedName.includes("api-key") ||
        normalizedName.includes("api_key") ||
        normalizedName.includes("apikey")
      const normalizedHeader = header.toLowerCase()
        .replaceAll("\t", " ")
        .replaceAll("\r", " ")
        .replaceAll("\n", " ")
      const headerTokens = normalizedHeader.split(" ").filter(Boolean)
      const hasInlineCredentials = headerTokens.some((token, index) =>
        (token === "bearer" || token === "basic") && Boolean(headerTokens[index + 1]),
      )
      if (hasSensitiveName || hasInlineCredentials) return undefined
    }
  }

  const sensitiveQueryKey = /(?:authorization|(?:^|[-_])auth(?:$|[-_])|cookie|api[-_]?key|(?:^|[-_])key(?:$|[-_])|access[-_]?token|token|secret|credential|password|signature|(?:^|[-_])sig(?:$|[-_]))/i
  if ([...requestURL.searchParams.keys()].some((key) => sensitiveQueryKey.test(key))) return undefined

  const hostname = requestURL.hostname.toLowerCase()
  const pathname = requestURL.pathname
  let subject: string | null = null
  let phase: ReconPhase = "asset_discovery"
  let subjectKey = ""

  if (hostname === "crt.sh" && pathname === "/") {
    subjectKey = "q"
    subject = requestURL.searchParams.get(subjectKey)
  } else if (hostname === "api.certspotter.com" && pathname === "/v1/issuances") {
    subjectKey = "domain"
    subject = requestURL.searchParams.get(subjectKey)
  } else if (hostname === "otx.alienvault.com") {
    const match = /^\/api\/v1\/indicators\/domain\/([^/]+)\/passive_dns\/?$/i.exec(pathname)
    if (match) {
      try {
        subject = decodeURIComponent(match[1]!)
        subjectKey = "domain"
      } catch {
        return undefined
      }
    }
  } else if (hostname === "web.archive.org" && pathname === "/cdx/search/cdx") {
    subjectKey = "url"
    subject = requestURL.searchParams.get(subjectKey)
    phase = "url_collection"
  }

  if (!subject) {
    // New public sources do not need to be added to a scanner/tool allowlist.
    // For generic passive APIs, require one unambiguous domain in a conventional
    // lookup query parameter. The provider itself must be outside target scope.
    const queryKeys = new Set(["domain", "domain_name", "hostname", "hostname_or_ip", "host", "target", "q", "query", "url", "search"])
    const candidates = [...requestURL.searchParams.entries()]
      .filter(([key]) => queryKeys.has(key.toLowerCase()))
      .map(([key, value]) => ({ key: key.toLowerCase(), value: normalizePassiveLookupDomain(value) }))
      .filter((item): item is { key: string; value: string } => Boolean(item.value))
    const domains = [...new Set(candidates.map((item) => item.value))]
    if (domains.length !== 1) return undefined
    subject = domains[0]!
    subjectKey = candidates.find((item) => item.value === subject)?.key ?? ""
    if (subjectKey === "url") phase = "url_collection"
  }

  const domain = normalizePassiveLookupDomain(subject)
  if (!domain) return undefined
  return { targetURL: "https://" + domain + "/", phase }
}

function normalizePassiveLookupDomain(value: string | null | undefined): string | undefined {
  if (!value) return undefined
  const domain = value.trim().toLowerCase()
    .replace(/^https?:\/\//i, "")
    .replace(/^[*%.]+/, "")
    .split(/[/?#]/, 1)[0]!
    .replace(/:\d+$/, "")
    .replace(/\.$/, "")
  return /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain) ? domain : undefined
}

const TARGET_LIST_FLAGS = new Set(["-l", "-list", "--list", "-dl", "-il", "-df", "--domain-file", "-domains", "--domains-file", "-targets", "--targets-file"])

async function readTargetListInputs(args: string[], cwd: string): Promise<{ present: boolean; targets: string[] }> {
  const files: string[] = []
  for (let i = 0; i < args.length; i++) {
    const flag = stripOuterShellQuotes(args[i]!).toLowerCase()
    if (TARGET_LIST_FLAGS.has(flag)) {
      const value = args[i + 1] ? stripOuterShellQuotes(args[i + 1]!) : ""
      if (!value || value.startsWith("-")) {
        throw new Error("Target-list mode requires a readable file path after " + flag + ".")
      }
      files.push(value)
      i++
      continue
    }
    const inline = [...TARGET_LIST_FLAGS].find((item) => flag.startsWith(item + "="))
    if (inline) {
      const value = stripOuterShellQuotes(args[i]!.slice(args[i]!.indexOf("=") + 1))
      if (!value) throw new Error("Target-list mode requires a readable file path after " + inline + ".")
      files.push(value)
    }
  }
  if (!files.length) return { present: false, targets: [] }

  const targets = new Set<string>()
  for (const file of files) {
    let raw: string
    try {
      raw = await fs.readFile(path.resolve(cwd, file), "utf8")
    } catch (error) {
      throw new Error("Cannot read target list " + file + ": " + (error instanceof Error ? error.message : String(error)))
    }
    for (const row of raw.split(/\r?\n/)) {
      const line = row.trim()
      if (!line || line.startsWith("#")) continue
      for (let value of line.split(",").map((item) => item.trim()).filter(Boolean)) {
        value = value.replace(/^\*\./, "")
        if (/^https?:\/\//i.test(value)) {
          let parsed: URL
          try { parsed = new URL(value) } catch { throw new Error("Invalid URL in target list " + file + ": " + value) }
          if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
            throw new Error("Target list contains a non-HTTP(S) or credentialed URL: " + value)
          }
          targets.add(parsed.href)
          continue
        }
        if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s]*)?$/i.test(value) &&
            !/^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$/.test(value)) {
          throw new Error("Target list contains an invalid hostname or URL: " + value)
        }
        targets.add("https://" + value)
      }
    }
  }
  if (!targets.size) throw new Error("Target list contains no usable hostnames or URLs.")
  return { present: true, targets: [...targets] }
}

/**
 * Prevent command-line HTTP clients from following a redirect to a second URL
 * without giving CyberStrike a chance to apply the persisted scope resolver.
 * Requests that do not follow redirects remain eligible for the ordinary
 * per-target scope check below.
 */
export function scannerRedirectScopeBlockReason(
  scannerInput: string,
  args: string[],
  launcherPrefix: string[] = [],
): string | undefined {
  const scanner = path.basename(stripOuterShellQuotes(scannerInput)).toLowerCase()
  const values = args.map(stripOuterShellQuotes)
  const prefix = launcherPrefix.map(stripOuterShellQuotes)
  if (scanner === "curl") {
    if (values[0] !== "-q" && values[0] !== "--disable") {
      return "curl may load ~/.curlrc, which can alter redirects and request behavior. Put -q (or --disable) first so the checked command is the effective command."
    }
    const followsRedirect = values.some((value) =>
      value === "--location" ||
      value === "--location-trusted" ||
      value.startsWith("--location=") ||
      /^-[^-]*L[A-Za-z]*$/.test(value),
    )
    if (followsRedirect) {
      return "curl redirect-follow options can issue a second request outside the persisted scope. Remove -L/--location or use a scope-aware request pipeline that checks every redirect target."
    }
  }
  if (scanner === "wget") {
    const configDisabled = prefix.some((value) => value.toLowerCase() === "env") &&
      prefix.some((value) => value === "WGETRC=/dev/null")
    if (!configDisabled && process.env.WGETRC !== "/dev/null") {
      return "wget can load ~/.wgetrc settings that enable recursion or change request behavior. Invoke it as env WGETRC=/dev/null wget --max-redirect=0 ... so the checked command uses no user configuration."
    }
    const optionIndexes = values
      .map((value, index) => ({ value, index }))
      .filter(({ value }) => value === "--max-redirect" || value.startsWith("--max-redirect="))
    if (optionIndexes.length !== 1) {
      return "wget follows redirects by default. Set exactly one explicit --max-redirect=0 so no redirected request can bypass persisted-scope checking."
    }
    const option = optionIndexes[0]!
    const value = option.value.startsWith("--max-redirect=")
      ? option.value.slice("--max-redirect=".length)
      : values[option.index + 1]
    if (value !== "0") {
      return "wget redirect following is blocked for generic shell mode. Set --max-redirect=0, or use a scope-aware request pipeline that checks every redirect target."
    }
  }
  return undefined
}

async function assertScannerReconGate(command: string[], commandText: string, cwd: string): Promise<void> {
  const scannerIndex = scannerExecutableIndex(command)
  if (scannerIndex < 0) {
    const executableIndex = commandExecutableIndex(command)
    const launchedScanner = executableIndex >= 0 ? await scannerLaunchedByWrapper(command, executableIndex) : undefined
    if (launchedScanner) {
      throw new Error("Recon execution gate blocked " + launchedScanner + " launched indirectly via a command wrapper. Target-list/executor wrappers cannot enforce per-request scope; invoke a scanner directly with explicit authorized inputs, or use the scope-aware request pipeline.")
    }
    // Inspect only payloads of an actual shell executable, including simple
    // launcher-prefixed forms such as "sudo bash -lc ...". Never search arbitrary
    // arguments of commands like grep/find for scanner names.
    const executable = executableIndex >= 0 ? path.basename(stripOuterShellQuotes(command[executableIndex]!)).toLowerCase() : ""
    const shellWrappers = SHELL_WRAPPERS
    if (shellWrappers.has(executable)) {
      const commandFlag = command.findIndex((value, index) => index > executableIndex && ["-c", "-lc", "-ec"].includes(stripOuterShellQuotes(value)))
      const payload = commandFlag >= 0 ? stripOuterShellQuotes(command[commandFlag + 1] ?? "") : ""
      const wrappedScanner = payload ? await findWrappedScanner(payload) : undefined
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
  const redirectReason = scannerRedirectScopeBlockReason(scanner, args, command.slice(0, scannerIndex))
  if (redirectReason) {
    throw new Error("Recon execution gate blocked " + scanner + ": " + redirectReason + " No network request was started.")
  }
  // These flags identify target-list modes for recon scanners. Do not apply this
  // generic check to curl/wget: curl's case-sensitive -L means "follow redirects",
  // and lowercasing it incorrectly turns it into the blocked "-l" list flag.
  // Target lists are allowed only after every concrete entry is parsed and
  // checked against the persisted scope below; the list itself grants no access.
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
  let phase = SCANNER_NOMINAL_PHASES[scanner]!
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
  const listedTargets = ["curl", "wget"].includes(scanner)
    ? { present: false, targets: [] as string[] }
    : await readTargetListInputs(args, cwd)
  if (listedTargets.present) targets = [...new Set([...targets, ...listedTargets.targets])]

  // Public read-only research APIs are contacted as providers, but authorization
  // is checked against the domain being queried, not the provider hostname.
  // The helper rejects writes, redirects, credentials, and unrecognized API routes.
  if (scanner === "curl" && targets.length === 1) {
    let requestURL: URL | undefined
    try { requestURL = new URL(targets[0]!) } catch {}
    if (requestURL) {
      const lookup = passiveResearchLookup(requestURL, args)
      if (lookup) {
        // Do not reinterpret an in-scope URL as a third-party source query.
        const providerScope = await TargetMemory.checkURLScope(requestURL.toString())
        if (!providerScope.allowed) {
          const subjectScope = await TargetMemory.checkURLScope(lookup.targetURL)
          if (subjectScope.allowed && subjectScope.workspace) {
            targets = [lookup.targetURL]
            phase = lookup.phase
          }
        }
      }
    }
  }
  if (!targets.length) {
    throw new Error("Recon execution gate blocked " + scanner + ": pass explicit target URL/host(s) or a readable target list so every concrete entry can be checked against persisted scope.")
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
        if (!currentScope || currentScope.status !== "configured" || currentScope.scopeItems.length === 0) {
          throw new Error("workspace " + current.targetURL + " has no configured persisted scope")
        }
        scopes.push(currentScope)
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
          throw new Error("Recon execution gate blocked katana for " + scopedURL + ": " + reason + " Use one explicit -u URL per authorized host, -fs fqdn, -rl 5, -d 3, and one stable absolute scratch -o path under that workspace's urls/ directory. Reuse it sequentially after normalizing and removing prior scratch output; do not create a new path per retry. No crawler command was started.")
        }
        const outputFlagIndex = args.findIndex((arg) => ["-o", "-output"].includes(stripOuterShellQuotes(arg).toLowerCase()))
        const outputPath = path.resolve(stripOuterShellQuotes(args[outputFlagIndex + 1]!))
        const urlsRoot = path.resolve(decision.workspace.workspacePath, "urls")
        try {
          const workspaceRealPath = await fs.realpath(decision.workspace.workspacePath)
          const urlsInfo = await fs.lstat(urlsRoot)
          const urlsRealPath = await fs.realpath(urlsRoot)
          if (urlsInfo.isSymbolicLink() || !urlsInfo.isDirectory() || urlsRealPath !== path.resolve(workspaceRealPath, "urls")) {
            throw new Error("the target workspace urls/ directory is missing, unsafe, or resolves outside the canonical workspace")
          }
        } catch (error) {
          throw new Error("Recon execution gate blocked katana because its URL artifact directory is not safe: " + (error instanceof Error ? error.message : String(error)) + ". No crawler command was started.")
        }
        try {
          await fs.lstat(outputPath)
          throw new Error("output file already exists")
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw new Error("Recon execution gate blocked katana because its output path already exists or cannot be checked: " + outputPath + ". If the file exists, inspect and normalize it first; remove it only after the normalized results are saved and verified, unless it is worth retaining as evidence. If the path cannot be inspected, fix that filesystem error rather than choosing another filename. Reuse the same stable scratch path for sequential attempts instead of creating a new file per retry. No crawler command was started.")
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

const DEFAULT_TIMEOUT = Flag.CYBERSTRIKE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS

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

const SHELL_WRAPPERS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"])

type BashCommandNode = { childCount: number; child(index: number): { type: string; text: string } | null }

function commandTokens(node: BashCommandNode): string[] {
  const command: string[] = []
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i)
    if (!child) continue
    if (["command_name", "word", "string", "raw_string", "concatenation"].includes(child.type)) command.push(child.text)
  }
  return command
}

/** Parse shell payloads as shell code, not regex text, so quoted arguments don't trigger false positives. */
export async function findWrappedScanner(payload: string): Promise<string | undefined> {
  const pending = [payload]
  const seen = new Set<string>()
  const parserInstance = await parser()

  while (pending.length > 0) {
    const script = pending.pop()!
    if (!script.trim() || seen.has(script)) continue
    seen.add(script)
    const tree = parserInstance.parse(script)
    if (!tree) continue

    for (const node of tree.rootNode.descendantsOfType("command")) {
      if (!node) continue
      const command = commandTokens(node)
      const scannerIndex = scannerExecutableIndex(command)
      if (scannerIndex >= 0) return path.basename(stripOuterShellQuotes(command[scannerIndex]!)).toLowerCase()

      const executableIndex = commandExecutableIndex(command)
      if (executableIndex < 0) continue
      // Also inspect non-shell launchers such as xargs/find/env inside a shell
      // payload, not only when they are the top-level BashTool command.
      const indirectlyLaunched = await scannerLaunchedByWrapper(command, executableIndex)
      if (indirectlyLaunched) return indirectlyLaunched
      const executable = path.basename(stripOuterShellQuotes(command[executableIndex]!)).toLowerCase()
      if (!SHELL_WRAPPERS.has(executable)) continue
      const commandFlag = command.findIndex((value, index) =>
        index > executableIndex && ["-c", "-lc", "-ec"].includes(stripOuterShellQuotes(value)),
      )
      const nested = commandFlag >= 0 ? stripOuterShellQuotes(command[commandFlag + 1] ?? "") : ""
      if (nested) pending.push(nested)
    }
  }
  return undefined
}

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
      if (params.timeout !== undefined && params.timeout <= 0) {
        throw new Error(`Invalid timeout value: ${params.timeout}. Provide a positive timeout or omit it for no automatic timeout.`)
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
      const scannerInvocationKeys = new Map<string, string>()

      for (const node of tree.rootNode.descendantsOfType("command")) {
        if (!node) continue

        // Get full command text including redirects if present
        let commandText = ["redirected_statement", "pipeline"].includes(node.parent?.type ?? "") ? node.parent!.text : node.text

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

        // Avoid repeating an identical scanner/source in one shell call, even if the
        // second command writes to another output path. Run once, then reuse its artifact.
        const scannerKey = reconScannerInvocationKey(command)
        if (scannerKey) {
          const previousCommand = scannerInvocationKeys.get(scannerKey)
          if (previousCommand) {
            throw new Error("Duplicate recon scanner invocation in one bash call. This scan has the same tool, target inputs, and options as an earlier command; changing only the output path does not justify repeating it. Reuse the first output or change the inputs/options for a genuinely distinct collection pass. First command: " + previousCommand.slice(0, 240))
          }
          scannerInvocationKeys.set(scannerKey, commandText)
        }

        // Enforce target scope + durable phase gates before known recon/scanner binaries start.
        await assertScannerReconGate(command, commandText, cwd)

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

      const timeoutTimer = timeout === undefined ? undefined : setTimeout(() => {
        timedOut = true
        void kill()
      }, timeout + 100)

      await new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          if (timeoutTimer) clearTimeout(timeoutTimer)
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
