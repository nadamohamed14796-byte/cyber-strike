import type { Argv } from "yargs"
import fs from "node:fs/promises"
import path from "node:path"
import { parseScopeFileContents, resolveScopeFilePath } from "../../target/scope-file"
import { cmd } from "./cmd"
import { Instance } from "../../project/instance"
import { TargetMemory, type TargetAssetType, type TargetNoteKind, type TargetNoteStatus } from "../../target"

const TargetInitCommand = cmd({
  command: "init <url>",
  describe: "create or open an isolated workspace for a target",
  builder: (yargs: Argv) => yargs.positional("url", { type: "string", demandOption: true }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const target = await TargetMemory.ensure(args.url)
        const requiredFiles = [
          path.join(target.workspacePath, "workspace.json"),
          path.join(target.workspacePath, "scope", "scope.json"),
          path.join(target.workspacePath, "notes.md"),
        ]
        for (const requiredFile of requiredFiles) {
          const info = await fs.stat(requiredFile).catch(() => undefined)
          if (!info?.isFile()) {
            throw new Error("Target workspace initialization failed: required file is missing: " + requiredFile)
          }
        }
        console.log("Target: " + target.targetURL)
        console.log("Workspace: " + target.workspacePath)
        console.log("Asset type: " + target.assetType)
        if (target.parentTargetID) console.log("Parent workspace ID: " + target.parentTargetID)
        console.log("Notes: " + path.join(target.workspacePath, "notes.md"))
        console.log("Workspace integrity: metadata, scope manifest, and notes verified")
        console.log("Created or verified target directories: scope, assets, recon, urls, requests, javascript, endpoints, testing, findings, evidence, reports, scans, runs, logs, sessions, research")
      },
    })
  },
})

const TargetListCommand = cmd({
  command: "list",
  describe: "list target workspaces for the current project",
  async handler() {
    await Instance.provide({
      directory: process.cwd(),
      fn() {
        const targets = TargetMemory.list()
        if (targets.length === 0) {
          console.log("No target workspaces yet. Create one with: cyberstrike target init <url>")
          return
        }
        for (const target of targets) {
          console.log((target.parentTargetID ? "  ↳ " : "") + "[" + target.assetType + "] " + target.targetURL + "\n  " + target.workspacePath)
        }
      },
    })
  },
})

const TargetShowCommand = cmd({
  command: "show <url>",
  describe: "show target metadata and saved notes",
  builder: (yargs: Argv) => yargs.positional("url", { type: "string", demandOption: true }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const target = await TargetMemory.get(args.url)
        if (!target) {
          console.log("Target not found. Create it with: cyberstrike target init " + args.url)
          return
        }
        const notes = TargetMemory.allNotes(target.id)
        console.log("Target: " + target.targetURL)
        console.log("Workspace: " + target.workspacePath)
        console.log("Asset type: " + target.assetType)
        if (target.parentTargetID) console.log("Parent workspace ID: " + target.parentTargetID)
        console.log("Saved notes: " + notes.length)
        for (const note of notes) {
          console.log("\n[" + note.status + "/" + note.kind + "] " + (note.title ?? "(untitled)"))
          console.log(note.content)
          if (note.sourceURL) console.log("Source: " + note.sourceURL)
        }
      },
    })
  },
})

const TargetScopeCommand = cmd({
  command: "scope <url>",
  describe: "show or configure an explicitly authorized target scope",
  builder: (yargs: Argv) =>
    yargs
      .positional("url", { type: "string", demandOption: true })
      .option("include", { type: "string", array: true, describe: "authorized domain, *.domain wildcard, or IPv4 CIDR (repeatable)" })
      .option("exclude", { type: "string", array: true, describe: "explicitly excluded domain, wildcard, or IPv4 CIDR (repeatable)" })
      .option("source", { type: "string", describe: "program or authorization source name" })
      .option("reference", { type: "string", describe: "HTTPS URL for the official program scope/policy" })
      .option("file", { type: "string", describe: "import exact in-scope entries from a UTF-8 text file (one host/domain/CIDR per line; blank lines and # comments ignored)" }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const requestedChange = Boolean(args.include?.length || args.exclude?.length || args.source || args.reference || args.file)
        if (requestedChange) {
          let fileEntries: string[] = []
          if (args.file) {
            const filePath = resolveScopeFilePath(args.file)
            let contents: string
            try {
              contents = await fs.readFile(filePath, "utf-8")
            } catch (error) {
              throw new Error("Cannot read scope file " + filePath + ": " + (error instanceof Error ? error.message : String(error)))
            }
            try {
              fileEntries = parseScopeFileContents(contents)
            } catch (error) {
              throw new Error((error instanceof Error ? error.message : String(error)) + " File: " + filePath)
            }
          }
          const includeEntries = [...(args.include ?? []), ...fileEntries]
          const result = await TargetMemory.configureScope(args.url, {
            include: includeEntries,
            exclude: args.exclude ?? [],
            authorizationSource: args.source ?? "",
            authorizationReference: args.reference ?? "",
          })
          const expectedFiles = [
            path.join(result.workspace.workspacePath, "workspace.json"),
            path.join(result.workspace.workspacePath, "scope", "scope.json"),
            path.join(result.workspace.workspacePath, "notes.md"),
          ]
          for (const expectedFile of expectedFiles) {
            const info = await fs.stat(expectedFile).catch(() => undefined)
            if (!info?.isFile()) {
              throw new Error("Scope was written but workspace integrity verification failed: required file is missing: " + expectedFile)
            }
          }
          console.log("Scope configured for: " + result.workspace.targetURL)
          console.log("Workspace: " + result.workspace.workspacePath)
          console.log("Notes: " + path.join(result.workspace.workspacePath, "notes.md"))
          console.log("Workspace integrity: metadata, scope manifest, and notes verified")
          console.log("Authorization source: " + result.scope.authorizationSource)
          console.log("Reference: " + result.scope.authorizationReference)
          console.log("Included entries: " + result.scope.scopeItems.length)
          if (args.file) console.log("Imported from: " + resolveScopeFilePath(args.file))
          console.log("Included: " + result.scope.scopeItems.slice(0, 20).join(", ") + (result.scope.scopeItems.length > 20 ? ", ... (showing first 20)" : ""))
          console.log("Excluded: " + (result.scope.excludedItems.join(", ") || "(none)"))
          console.log("Existing workspaces newly linked/reorganized: " + result.associatedAssets.length)
          console.log("Scope file: " + path.join(result.workspace.workspacePath, "scope", "scope.json"))
          console.log("Review the official program policy before active testing; this manifest records your explicit scope decision.")
          return
        }

        const scope = await TargetMemory.getScope(args.url)
        if (!scope) {
          console.log("No target workspace exists. Create one with: cyberstrike target init " + args.url)
          return
        }
        console.log("Target: " + scope.targetURL)
        console.log("Status: " + scope.status)
        console.log("Included: " + (scope.scopeItems.join(", ") || "(none)"))
        console.log("Excluded: " + (scope.excludedItems.join(", ") || "(none)"))
        console.log("Authorization source: " + (scope.authorizationSource ?? "(not configured)"))
        console.log("Reference: " + (scope.authorizationReference ?? "(not configured)"))
        if (scope.status !== "configured") {
          console.log("WARNING: Scope is unconfigured. Do not perform active testing.")
          console.log("Configure with --include <domain> --source <program> --reference <official-https-url>.")
        }
      },
    })
  },
})


const TargetTreeCommand = cmd({
  command: "tree <url>",
  describe: "show a target and all nested in-scope assets",
  builder: (yargs: Argv) => yargs.positional("url", { type: "string", demandOption: true }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const root = await TargetMemory.get(args.url)
        if (!root) {
          console.log("Target not found. Create it with: cyberstrike target init " + args.url)
          return
        }
        const all = TargetMemory.list()
        const byParent = new Map<string, typeof all>()
        for (const item of all) {
          if (!item.parentTargetID) continue
          const siblings = byParent.get(item.parentTargetID) ?? []
          siblings.push(item)
          byParent.set(item.parentTargetID, siblings)
        }
        const seen = new Set<string>()
        const print = (item: (typeof all)[number], depth: number) => {
          if (seen.has(item.id)) {
            console.log("  ".repeat(depth) + "[cycle refused] " + item.targetURL)
            return
          }
          seen.add(item.id)
          console.log("  ".repeat(depth) + (depth ? "└─ " : "") + "[" + item.assetType + "] " + item.targetURL)
          console.log("  ".repeat(depth + 1) + item.workspacePath)
          for (const child of byParent.get(item.id) ?? []) print(child, depth + 1)
        }
        print(root, 0)
      },
    })
  },
})

const TargetAttachCommand = cmd({
  command: "attach <parent> <asset>",
  describe: "attach an asset to a parent only when the saved scope explicitly authorizes it",
  builder: (yargs: Argv) =>
    yargs
      .positional("parent", { type: "string", demandOption: true, describe: "existing program/parent target URL" })
      .positional("asset", { type: "string", demandOption: true, describe: "authorized child host URL" })
      .option("kind", {
        type: "string",
        choices: ["subdomain", "application", "api", "host"] as const,
      }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const result = await TargetMemory.attachAsset(args.parent, args.asset, args.kind as TargetAssetType | undefined)
        console.log("Asset attached under: " + result.parent.targetURL)
        console.log("Asset: " + result.asset.targetURL)
        console.log("Type: " + result.asset.assetType)
        console.log("Workspace: " + result.asset.workspacePath)
      },
    })
  },
})

const TargetNoteCommand = cmd({
  command: "note <url> <content>",
  describe: "save a durable note to SQLite and the target notes.md file",
  builder: (yargs: Argv) =>
    yargs
      .positional("url", { type: "string", demandOption: true })
      .positional("content", { type: "string", demandOption: true })
      .option("title", { type: "string", describe: "short note title" })
      .option("kind", {
        type: "string",
        choices: ["manual", "asset", "endpoint", "javascript", "finding", "evidence", "research", "lesson"] as const,
        default: "manual",
      })
      .option("status", {
        type: "string",
        choices: ["unverified", "observed", "confirmed", "disproven"] as const,
        default: "observed",
      })
      .option("source", { type: "string", default: "manual" })
      .option("source-url", { type: "string", describe: "public/source URL; credentials and query parameters are removed" })
      .option("evidence", { type: "string", describe: "concrete evidence required for confirmed/disproven status" })
      .option("tags", { type: "string", describe: "comma-separated tags" }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const result = await TargetMemory.addNote(args.url, {
          content: args.content,
          evidence: args.evidence,
          title: args.title,
          kind: args.kind as TargetNoteKind,
          status: args.status as TargetNoteStatus,
          source: args.source,
          sourceURL: args.sourceUrl,
          tags: args.tags?.split(","),
        })
        console.log((result.created ? "Saved note" : "Note already exists") + ": " + result.note.id)
        console.log("Target: " + result.workspace.targetURL)
        console.log("Workspace: " + result.workspace.workspacePath)
        console.log("Database: durable target_note record")
        console.log("File: " + result.workspace.workspacePath + "/notes.md")
      },
    })
  },
})

export const TargetCommand = cmd({
  command: "target",
  describe: "manage target-specific memory and workspace directories",
  builder: (yargs: Argv) =>
    yargs
      .command(TargetInitCommand)
      .command(TargetListCommand)
      .command(TargetShowCommand)
      .command(TargetScopeCommand)
      .command(TargetTreeCommand)
      .command(TargetAttachCommand)
      .command(TargetNoteCommand)
      .demandCommand(),
  async handler() {},
})
