import z from "zod"
import { spawn } from "child_process"
import { Tool } from "./tool"
import path from "path"
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
import { TargetMemory } from "../target"
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
  paramspider: "url_collection",
  arjun: "endpoint_inventory",
  nuclei: "vulnerability_testing",
  ffuf: "vulnerability_testing",
  feroxbuster: "vulnerability_testing",
  gobuster: "vulnerability_testing",
  dirsearch: "vulnerability_testing",
  dirb: "vulnerability_testing",
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

async function assertScannerReconGate(command: string[], commandText: string): Promise<void> {
  const scannerIndex = command.findIndex((value) => SCANNER_PHASES[path.basename(value).toLowerCase()] !== undefined)
  if (scannerIndex < 0) {
    const wrappedScanner = Object.keys(SCANNER_PHASES).find((name) => new RegExp("\\b" + name + "\\b", "i").test(commandText))
    if (wrappedScanner) {
      throw new Error("Recon execution gate blocked an indirect/wrapped " + wrappedScanner + " invocation. Run the scanner as a direct command so target scope and phase prerequisites can be checked.")
    }
    return
  }
  const scanner = path.basename(command[scannerIndex]!).toLowerCase()
  const args = command.slice(scannerIndex + 1)
  if (args.some((value) => ["--help", "-h", "--version", "-version", "-V"].includes(value)) &&
      !args.some((value) => /^https?:\/\//i.test(value))) return
  if (["katana", "hakrawler", "gospider"].includes(scanner)) {
    throw new Error("Recon execution gate blocked " + scanner + " in generic shell mode because its crawl can follow off-scope links. Use the scope-aware browser/recon pipeline so every discovered URL is checked before a request.")
  }
  if (args.some((value) => ["-l", "-list", "--list", "-dl", "-il", "-targets", "--targets-file"].includes(value.toLowerCase()))) {
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
  const phase = SCANNER_PHASES[scanner]!
  const targets = scannerTargets(command.slice(scannerIndex), commandText)
  if (!targets.length) {
    throw new Error("Recon execution gate blocked " + scanner + ": pass explicit target URL/host(s). Target-list/file mode is blocked until each target can be checked against persisted scope and phase checkpoints.")
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
