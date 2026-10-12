import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { Instance } from "../../project/instance"
import { TargetMemory, type TargetNoteKind, type TargetNoteStatus } from "../../target"

const TargetInitCommand = cmd({
  command: "init <url>",
  describe: "create or open an isolated workspace for a target",
  builder: (yargs: Argv) => yargs.positional("url", { type: "string", demandOption: true }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const target = await TargetMemory.ensure(args.url)
        console.log("Target: " + target.targetURL)
        console.log("Workspace: " + target.workspacePath)
        console.log("Notes: " + target.workspacePath + "/notes.md")
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
          console.log(target.targetURL + "\n  " + target.workspacePath)
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
      .command(TargetNoteCommand)
      .demandCommand(),
  async handler() {},
})
