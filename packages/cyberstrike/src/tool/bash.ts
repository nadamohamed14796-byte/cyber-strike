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
import type { ReconPhase } from "../target/recon-gate"

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
 * Generic CLI input metadata. This describes argument shapes, not a list of
 * supported or preferred tools. Any executable with a concrete target argument
 * or a recognizable target-list input is routed through the same scope gate.
 *
 * Help/version inspection and tool selection remain the planner's responsibility:
 * the runner must not infer that an unregistered executable is automatically safe.
 */
const TARGET_ARGUMENT_FLAGS = new Set([
  "-u", "--url", "--urls", "--url-list", "-target", "--target", "--target-url",
  "--target-host", "--target-domain", "-host", "--host", "--hostname", "--hostnames",
  "-d", "--domain", "--domains", "--domain-name", "-t", "-h", "--scope", "--origin",
  "--input", "-i", "--input-url", "--endpoint", "--base-url",
])
const TARGET_LIST_FLAGS = new Set([
  "-l", "-list", "--list", "-dl", "-il", "-df", "--domain-file", "-domains",
  "--domains-file", "-targets", "--targets-file", "--target-list", "--input-list",
  "--host-list", "--hosts-file", "--input-file", "--list-file", "--domain-list",
  "--domains-list", "--hostname-list", "--hostnames-file", "-f", "--file", "-i", "--input",
])
const EXPLICIT_TARGET_LIST_FLAGS = new Set([
  "-l", "-list", "--list", "-dl", "-il", "-df", "--domain-file", "-domains",
  "--domains-file", "-targets", "--targets-file", "--target-list", "--input-list",
  "--host-list", "--hosts-file", "--input-file", "--list-file", "--domain-list",
  "--domains-list", "--hostname-list", "--hostnames-file",
])
// Infer list/input options by semantic shape as well as common conventions, so
// new CLIs do not need executable-name-specific parser branches.
function normalizedOptionName(value: string): string {
  const token = stripOuterShellQuotes(value).toLowerCase()
  return token.includes("=") ? token.slice(0, token.indexOf("=")) : token
}

function isTargetListFlag(value: string): boolean {
  const flag = normalizedOptionName(value)
  if (TARGET_LIST_FLAGS.has(flag)) return true
  const name = flag.replace(/^-+/, "")
  if (/(?:wordlist|template|output|outfile|exclude|blacklist|allowlist|blocklist)/.test(name)) return false
  const targetNoun = /(?:target|targets|domain|domains|host|hosts|hostname|hostnames|scope|input|url|urls|asset|assets)/.test(name)
  const fileShape = /(?:file|list|path|batch|source|csv|tsv|jsonl?|txt)$/.test(name) ||
    /(?:file|list|path|batch|source)(?:[-_]|$)/.test(name) ||
    /^(?:targets|domains|hosts|hostnames|urls|assets)$/.test(name)
  return targetNoun && fileShape
}

function isExplicitTargetListFlag(value: string): boolean {
  const flag = normalizedOptionName(value)
  if (EXPLICIT_TARGET_LIST_FLAGS.has(flag)) return true
  if (["-f", "--file", "-i", "--input"].includes(flag)) return false
  return isTargetListFlag(flag)
}

function isDirectTargetValue(value: string): boolean {
  if (isTargetLikeValue(value)) return true
  const pieces = value.split(",").map((entry) => entry.trim()).filter(Boolean)
  return pieces.length > 1 && pieces.every((entry) => isTargetLikeValue(entry))
}

const CLI_OPTIONS_WITH_NON_TARGET_VALUES = new Set([
  "-o", "--o", "--output", "-output", "--output-file", "-out", "-on", "-ox", "-og", "-oa",
  "-w", "--wordlist", "--word-list", "-p", "--ports", "--port", "-port", "--top-ports",
  "-rate", "--rate", "--min-rate", "--max-rate", "--threads", "-threads", "--timeout",
  "-timeout", "--retries", "--proxy", "--proxy-url", "--proxy-list", "-x",
  "--header", "--headers", "--user-agent", "-ua", "--cookie",
  "--api-key", "--token", "--api-token", "--username", "--password", "--config",
  "--template", "-template", "--format", "-of", "--severity", "--exclude",
])
const LOCAL_TEXT_PROCESSORS = new Set([
  "echo", "printf", "cat", "head", "tail", "sed", "awk", "grep", "egrep", "fgrep",
  "rg", "sort", "uniq", "tr", "cut", "paste", "wc", "tee", "jq", "yq",
  "basename", "dirname", "realpath", "pwd", "ls", "stat", "file", "test",
  "true", "false", "date", "whoami", "id", "envsubst", "column", "fold",
  "strings", "sha256sum", "md5sum", "xxd", "od", "diff", "cmp",
  "mkdir", "touch", "cp", "mv", "rm", "chmod", "chown", "ln", "rmdir",
  "find", "xargs", "parallel",
])
const SHELL_LAUNCHERS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"])
const COMMAND_WRAPPERS = new Set(["xargs", "parallel", "find", "env"])
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

export function scannerExecutableIndex(command: string[], commandText = ""): number {
  const executableIndex = commandExecutableIndex(command)
  if (executableIndex < 0) return -1
  const executable = path.basename(stripOuterShellQuotes(command[executableIndex]!)).toLowerCase()

  // Let wrapper handling inspect the real nested executable. Likewise, local
  // text/file utilities should not be mistaken for network tools merely because
  // a URL or hostname appears in their input.
  if (SHELL_LAUNCHERS.has(executable) || COMMAND_WRAPPERS.has(executable) || LOCAL_TEXT_PROCESSORS.has(executable)) {
    return -1
  }

  const invocation = command.slice(executableIndex)
  if (scannerTargets(invocation, commandText).length > 0) return executableIndex
  if (hasTargetListInputArgument(invocation.slice(1))) return executableIndex
  // Dynamic stdin hides concrete targets from argv. A non-local executable at
  // the receiving end of a pipeline must be routed through the gate; if its
  // targets cannot be proven from literal input or an explicit list, it fails
  // closed rather than silently executing an unchecked network request.
  if (commandText.includes("|")) return executableIndex
  return -1
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

function isTargetLikeValue(rawValue: string): boolean {
  const value = stripOuterShellQuotes(rawValue).trim().replace(/[),;]+$/, "")
  if (!value || value.startsWith("-")) return false
  if (/^https?:\/\//i.test(value)) {
    try {
      const parsed = new URL(value)
      return ["http:", "https:"].includes(parsed.protocol) && !parsed.username && !parsed.password
    } catch {
      return false
    }
  }
  const candidate = value.replace(/^\*\./, "")
  const hasPath = candidate.includes("/")
  // Do not treat bare output/list/config filenames as DNS names. A real URL
  // such as example.com/robots.txt is still a target and is handled separately.
  if (!hasPath && /\.(?:txt|list|csv|tsv|json|jsonl|xml|yaml|yml|log|md|html|js|map|pdf|dict|lst|hosts|urls)$/i.test(candidate)) {
    return false
  }
  return /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s]*)?$/i.test(candidate) ||
    /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/[^\s]*)?$/.test(candidate)
}

function addNormalizedTarget(candidates: Set<string>, rawValue: string): void {
  const value = stripOuterShellQuotes(rawValue).trim().replace(/[),;]+$/, "")
  if (!value || value.startsWith("-")) return
  if (/^https?:\/\//i.test(value)) {
    if (isTargetLikeValue(value)) candidates.add(value)
    return
  }
  // Comma-separated hostname lists are common input syntax. Splitting is only
  // attempted when the item is not a URL, so query-string commas remain intact.
  for (let candidate of value.split(",")) {
    candidate = candidate.trim().replace(/^\*\./, "")
    if (!isTargetLikeValue(candidate)) continue
    candidates.add("https://" + candidate)
  }
}

function hasTargetListInputArgument(args: string[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const raw = stripOuterShellQuotes(args[i]!).toLowerCase()
    const inlineFlag = raw.includes("=") ? raw.slice(0, raw.indexOf("=")) : raw
    if (!isTargetListFlag(inlineFlag)) continue
    const value = raw.includes("=")
      ? stripOuterShellQuotes(args[i]!.slice(args[i]!.indexOf("=") + 1))
      : stripOuterShellQuotes(args[i + 1] ?? "")
    if (!value || value.startsWith("-")) return true
    if (isDirectTargetValue(value)) continue
    if (isExplicitTargetListFlag(inlineFlag) ||
        /[\\/]/.test(value) ||
        /\.(?:txt|list|csv|tsv|jsonl?|yaml|yml|hosts|urls|lst)$/i.test(value)) {
      return true
    }
  }
  return false
}

/**
 * Extract concrete target candidates without requiring a hardcoded executable
 * name. Positional domains, URLs, generic target options, and literal hostname
 * producers in pipelines are all parsed using the same rules. Every returned
 * candidate is still checked against the persisted scope before execution.
 */
export function scannerTargets(command: string[], commandText: string): string[] {
  const candidates = new Set<string>()

  // In a pipeline, commandText contains neighboring commands too. Never borrow
  // an upstream seed URL as proof of the downstream command's actual stdin
  // targets; parse this argv and literal producers below.
  if (!commandText.includes("|")) {
    for (const match of commandText.matchAll(/https?:\\/\\/[^\\s"'<>`]+/gi)) {
      addNormalizedTarget(candidates, match[0])
    }
  }

  // Common value-taking options whose values are not the target: output paths,
  // wordlists, ports, rates, proxy settings, headers, credentials, and configs.
  // Unknown options are not special-cased; domain-like values remain visible to
  // the generic parser so newly installed CLIs do not need a code change.
  for (let i = 1; i < command.length; i++) {
    const token = stripOuterShellQuotes(command[i]!).trim()
    if (!token) continue
    const lower = token.toLowerCase()
    const flag = lower.includes("=") ? lower.slice(0, lower.indexOf("=")) : lower

    if (CLI_OPTIONS_WITH_NON_TARGET_VALUES.has(flag)) {
      if (!lower.includes("=")) i++
      continue
    }
    if (isTargetListFlag(flag)) {
      const next = lower.includes("=") ? token.slice(token.indexOf("=") + 1) : command[i + 1]
      if (next) addNormalizedTarget(candidates, next)
      if (!lower.includes("=")) i++
      continue
    }
    if (TARGET_ARGUMENT_FLAGS.has(flag)) {
      const next = lower.includes("=") ? token.slice(token.indexOf("=") + 1) : command[i + 1]
      if (next) addNormalizedTarget(candidates, next)
      if (!lower.includes("=")) i++
      continue
    }
    if (token.startsWith("-") && lower.includes("=")) {
      // For unregistered CLIs, an arbitrary option value can still be a target.
      // Generic validation is safer than treating new option names as trusted.
      addNormalizedTarget(candidates, token.slice(token.indexOf("=") + 1))
      continue
    }
    if (token.startsWith("-")) continue
    addNormalizedTarget(candidates, token)
  }

  // Literal hostnames piped from echo/printf are visible even when the receiving
  // CLI consumes stdin instead of argv. Never infer authorization from a file
  // name (for example domains.txt); file-backed inputs must use an explicit list
  // option so every line can be parsed and scope-checked before execution.
  if (commandText.includes("|")) {
    const pipelineIndex = commandText.lastIndexOf("|")
    const inputText = commandText.slice(0, pipelineIndex).trim()
    // Only a literal producer immediately before the receiving command is
    // statically enumerable. Never treat an upstream scanner seed as proof of
    // the dynamic hosts that it may emit.
    if (/^(?:printf|echo)\b/i.test(inputText)) {
      const hostPattern = /(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s"'<>\x60]*)?/gi
      for (const match of inputText.matchAll(hostPattern)) {
        const value = match[0].replace(/\.$/, "")
        if (isTargetLikeValue(value)) addNormalizedTarget(candidates, value)
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

  // Rate and depth are operator/tool choices, not authorization gates. Validate
  // them only when explicitly supplied; do not silently impose a rate ceiling or
  // a mandatory crawl depth on otherwise in-scope work.
  const rateIndex = normalizedArgs.findIndex((arg) => ["-rl", "--rate-limit"].includes(arg))
  if (rateIndex >= 0) {
    const rate = Number(stripOuterShellQuotes(args[rateIndex + 1] ?? ""))
    if (!Number.isInteger(rate) || rate < 1) {
      return "Katana rate limit must be a positive integer when supplied."
    }
  }
  const depthIndex = normalizedArgs.findIndex((arg) => ["-d", "--depth"].includes(arg))
  if (depthIndex >= 0) {
    const depth = Number(stripOuterShellQuotes(args[depthIndex + 1] ?? ""))
    if (!Number.isSafeInteger(depth) || depth < 1) {
      return "Katana depth must be a positive safe integer when supplied."
    }
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
    return name || undefined
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

  // A wildcard CT/archive query (for example %.example.com or
  // *.example.com/*) describes authorized subdomains, not the apex domain.
  // Scope-check a concrete synthetic child so a policy containing only
  // *.example.com can authorize the passive lookup without accidentally
  // requiring example.com itself to be in scope. This URL is only a scope
  // subject; curl still contacts the public passive-research provider above.
  const rawSubject = subject.trim()
  const wildcardLookup = /^(?:\*|%|%2a)\./i.test(rawSubject)
  const scopeHost = wildcardLookup ? "cyberstrike-scope-check." + domain : domain
  return { targetURL: "https://" + scopeHost + "/", phase }
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

async function pathIsFile(file: string, cwd: string): Promise<boolean> {
  try {
    return (await fs.stat(path.resolve(cwd, file))).isFile()
  } catch {
    return false
  }
}

export async function readTargetListInputs(
  args: string[],
  cwd: string,
): Promise<{ present: boolean; targets: string[] }> {
  const files: Array<{ path: string; strict: boolean }> = []
  const fileLike = (value: string) =>
    /[\\/]/.test(value) ||
    /\.(?:txt|list|csv|tsv|jsonl?|xml|yaml|yml|hosts|urls|lst)$/i.test(value)

  for (let i = 0; i < args.length; i++) {
    const raw = stripOuterShellQuotes(args[i]!).toLowerCase()
    const inlineFlag = raw.includes("=") ? raw.slice(0, raw.indexOf("=")) : raw
    if (!isTargetListFlag(inlineFlag)) continue

    const inline = raw.includes("=")
    const value = inline
      ? stripOuterShellQuotes(args[i]!.slice(args[i]!.indexOf("=") + 1))
      : stripOuterShellQuotes(args[i + 1] ?? "")
    if (!value || value.startsWith("-")) {
      if (isExplicitTargetListFlag(inlineFlag)) {
        throw new Error("Target-list mode requires a readable file path after " + inlineFlag + ".")
      }
      continue
    }

    // A hostname/URL supplied to an input option is a direct target, not a file.
    // Ambiguous file/input flags are treated as lists only when the value looks
    // like a path, has a list extension, or resolves to an existing file.
    if (isDirectTargetValue(value)) {
      if (!inline) i++
      continue
    }
    const exists = await pathIsFile(value, cwd)
    const shouldRead = isExplicitTargetListFlag(inlineFlag) ||
      fileLike(value) || exists
    if (!shouldRead) {
      if (!inline) i++
      continue
    }
    files.push({ path: value, strict: isExplicitTargetListFlag(inlineFlag) })
    if (!inline) i++
  }
  if (!files.length) return { present: false, targets: [] }

  const targets = new Set<string>()
  for (const item of files) {
    let raw: string
    try {
      raw = await fs.readFile(path.resolve(cwd, item.path), "utf8")
    } catch (error) {
      throw new Error("Cannot read target list " + item.path + ": " + (error instanceof Error ? error.message : String(error)))
    }

    let recognized = 0
    for (const row of raw.split(/\r?\n/)) {
      const line = row.trim()
      if (!line || line.startsWith("#")) continue
      const values = line.split(",").map((entry) => entry.trim()).filter(Boolean)
      for (const sourceValue of values) {
        const value = sourceValue.replace(/^\*\./, "")
        if (/^https?:\/\//i.test(value)) {
          let parsed: URL
          try {
            parsed = new URL(value)
          } catch {
            if (item.strict) throw new Error("Invalid URL in target list " + item.path + ": " + value)
            continue
          }
          if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
            if (item.strict) throw new Error("Target list contains a non-HTTP(S) or credentialed URL: " + value)
            continue
          }
          targets.add(parsed.href)
          recognized++
          continue
        }
        if (!isTargetLikeValue(value)) {
          if (item.strict) throw new Error("Target list contains an invalid hostname or URL: " + value)
          continue
        }
        if (/^\d/.test(value) || value.includes(".")) {
          targets.add("https://" + value)
          recognized++
        }
      }
    }

    if (!recognized && item.strict) {
      throw new Error("Target list " + item.path + " contains no usable hostnames or URLs.")
    }
  }

  if (!targets.size) return { present: false, targets: [] }
  return { present: true, targets: [...targets] }
}
/** Parse explicit port lists and ranges so persisted scope is checked for every port. */
export function parseScopedPortSpec(spec: string): number[] | undefined {
  const value = spec.trim()
  if (!value) return undefined
  const ports = new Set<number>()
  for (const part of value.split(",")) {
    const match = /^(\d+)(?:-(\d+))?$/.exec(part.trim())
    if (!match) return undefined
    const start = Number(match[1])
    const end = Number(match[2] ?? match[1])
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65535 || start > end) return undefined
    for (let port = start; port <= end; port++) ports.add(port)
  }
  return ports.size ? [...ports].sort((a, b) => a - b) : undefined
}

async function assertScannerReconGate(command: string[], commandText: string, cwd: string): Promise<void> {
  const scannerIndex = scannerExecutableIndex(command, commandText)
  if (scannerIndex < 0) {
    const executableIndex = commandExecutableIndex(command)
    const launchedScanner = executableIndex >= 0 ? await scannerLaunchedByWrapper(command, executableIndex) : undefined
    if (launchedScanner) {
      // Wrapper commands need their own target extraction before execution. Do not
      // reject based on tool identity alone; continue only when the nested scanner
      // can be identified and its concrete target can be checked below.
      const wrapperArgs = command.slice(executableIndex + 1)
      const nestedScannerIndex = wrapperArgs.findIndex((value) =>
        path.basename(stripOuterShellQuotes(value)).toLowerCase() === launchedScanner,
      )
      if (nestedScannerIndex >= 0) {
        const nested = wrapperArgs.slice(nestedScannerIndex)
        // Re-run the complete scanner gate on the extracted invocation so port
        // restrictions, redirect handling, target-list parsing, and every target
        // check are identical to a direct scanner invocation.
        await assertScannerReconGate(nested, commandText, cwd)
        return
      }
      throw new Error("Cannot verify the target for wrapped " + launchedScanner + " command. Run it directly with explicit in-scope targets.")
    }
    // Inspect only payloads of an actual shell executable, including simple
    // launcher-prefixed forms such as "sudo bash -lc ...". Never search arbitrary
    // arguments of commands like grep/find for scanner names.
    const executable = executableIndex >= 0 ? path.basename(stripOuterShellQuotes(command[executableIndex]!)).toLowerCase() : ""
    const shellWrappers = SHELL_WRAPPERS
    if (shellWrappers.has(executable)) {
      const commandFlag = command.findIndex((value, index) => index > executableIndex && ["-c", "-lc", "-ec"].includes(stripOuterShellQuotes(value)))
      const payload = commandFlag >= 0 ? stripOuterShellQuotes(command[commandFlag + 1] ?? "") : ""
      const wrappedInvocation = payload ? await findWrappedScannerInvocation(payload) : undefined
      if (wrappedInvocation?.length) {
        // Apply the same complete target/port/redirect checks to the nested
        // scanner rather than blocking the shell wrapper by tool identity.
        await assertScannerReconGate(wrappedInvocation, payload, cwd)
      }
    }
    return
  }
  const scanner = path.basename(command[scannerIndex]!).toLowerCase()
  const args = command.slice(scannerIndex + 1)
  if (args.some((value) => ["--help", "-h", "--version", "-version", "-V"].includes(value)) &&
      !args.some((value) => /^https?:\/\//i.test(value))) return
  // Do not blanket-disable a scanner because of its name. Every explicit input
  // still has to pass persisted scope checks below; redirect-capable clients
  // remain subject to the request-scope checks in scannerRequestScopeBlockReason.
  const redirectReason = scannerRequestScopeBlockReason(scanner, args, command.slice(0, scannerIndex))
  if (redirectReason) {
    throw new Error("Cannot run " + scanner + ": " + redirectReason + " No network request was started.")
  }
  // These flags identify target-list modes for recon scanners. Do not apply this
  // generic check to curl/wget: curl's case-sensitive -L means "follow redirects",
  // and lowercasing it incorrectly turns it into the blocked "-l" list flag.
  // Target lists are allowed only after every concrete entry is parsed and
  // checked against the persisted scope below; the list itself grants no access.
  let portScanPorts: number[] | undefined
  const portFlag = args.findIndex((value) => ["--ports", "--port", "-port"].includes(value.toLowerCase()) || value === "-p")
  const portSpec = portFlag >= 0 ? args[portFlag + 1] : undefined
  // A recognized explicit port-list option is enforced regardless of which CLI
  // implements it. Never let a new scanner evade port policy by being unlisted.
  if (portSpec && (["--ports", "-port"].includes(args[portFlag]!.toLowerCase()) || /^\d+(?:[-,]\d+)*$/.test(portSpec))) {
    const parsedPorts = parseScopedPortSpec(portSpec)
    if (!parsedPorts) {
      if (["--ports", "--port", "-port"].includes(args[portFlag]!.toLowerCase())) {
        throw new Error("Cannot run " + scanner + ": invalid explicit port specification " + portSpec + ". No command was started.")
      }
    } else {
      portScanPorts = parsedPorts
    }
  }
  // Tool choice is not restricted by a phase allowlist. Request safety and
  // persisted target-scope validation below remain in force.
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
          }
        }
      }
    }
  }
  if (!targets.length) {
    throw new Error("Cannot run " + scanner + ": pass explicit target URL/host(s) or a readable target list so every concrete entry can be checked against persisted scope.")
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
      throw new Error("Cannot run " + scanner + ": could not normalize target " + target)
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
        throw new Error("Cannot run " + scanner + " for " + scopedURL + ": persisted scope rejected the target/port (" + decision.reason + "). No command was started.")
      }
      if (scanner === "katana") {
        let scopes: TargetScope[]
        try {
          scopes = await scopesForWorkspace(decision.workspace)
        } catch (error) {
          throw new Error("Cannot run katana for " + scopedURL + ": unable to verify all inherited scope layers (" + (error instanceof Error ? error.message : String(error)) + "). No command was started.")
        }
        const reason = katanaScopeBlockReason(args, scopedURL, scopes, decision.workspace.workspacePath)
        if (reason) {
          throw new Error("Cannot run katana for " + scopedURL + ": " + reason + " Use an explicit in-scope URL, preserve the FQDN crawl boundary, and save output inside the target workspace's urls/ directory. No command was started.")
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
          throw new Error("Cannot run katana because its URL artifact directory is not safe: " + (error instanceof Error ? error.message : String(error)) + ". No command was started.")
        }
        try {
          const outputInfo = await fs.lstat(outputPath)
          // Reuse an existing regular artifact path; only reject links/non-files
          // that could redirect writes outside the validated workspace.
          if (outputInfo.isSymbolicLink() || !outputInfo.isFile()) {
            throw new Error("output path exists but is not a regular file")
          }
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw new Error("Cannot run katana because its output path is unsafe or cannot be checked: " + outputPath + " (" + (error instanceof Error ? error.message : String(error)) + "). No command was started.")
          }
        }
      }
      // Phase/checkpoint metadata must not act as a scanner allowlist.
      // The concrete URL/port has already passed the persisted scope matcher above.
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
export async function findWrappedScannerInvocation(payload: string): Promise<string[] | undefined> {
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
      const scannerIndex = scannerExecutableIndex(command, commandText)
      if (scannerIndex >= 0) return command.slice(scannerIndex)

      const executableIndex = commandExecutableIndex(command)
      if (executableIndex < 0) continue
      const indirectlyLaunched = await scannerLaunchedByWrapper(command, executableIndex)
      if (indirectlyLaunched) {
        const nestedIndex = command.findIndex((value) =>
          path.basename(stripOuterShellQuotes(value)).toLowerCase() === indirectlyLaunched,
        )
        if (nestedIndex >= 0) return command.slice(nestedIndex)
      }
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

export async function findWrappedScanner(payload: string): Promise<string | undefined> {
  const invocation = await findWrappedScannerInvocation(payload)
  if (!invocation?.length) return undefined
  return path.basename(stripOuterShellQuotes(invocation[0]!)).toLowerCase()
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
        )
        .optional(),
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

        // Apply request safety and persisted target-scope checks before a target-aware CLI starts, including executables not previously cataloged by name.
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
      // Match ensure_tools verification paths during real command execution.
      // Otherwise a Go/pipx/Cargo tool can be reported installed but remain unlaunchable.
      const home = process.env.HOME
      const toolBinDirs = home
        ? [path.join(home, "go", "bin"), path.join(home, ".local", "bin"), path.join(home, ".cargo", "bin")]
        : []
      const shellEnvPath = (shellEnv.env as { PATH?: string }).PATH
      const effectivePath = [...new Set([
        ...(typeof shellEnvPath === "string" ? shellEnvPath.split(path.delimiter) : []),
        ...(process.env.PATH ?? "").split(path.delimiter),
        ...toolBinDirs,
      ].filter(Boolean))].join(path.delimiter)
      const proc = spawn(params.command, {
        shell,
        cwd,
        env: {
          ...process.env,
          ...shellEnv.env,
          PATH: effectivePath,
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
        title: params.description ?? "Run shell command",
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
