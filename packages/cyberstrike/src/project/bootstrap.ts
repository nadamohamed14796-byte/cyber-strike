import { Plugin } from "../plugin"
import { Format } from "../format"
import { LSP } from "../lsp"
import { FileWatcher } from "../file/watcher"
import { File } from "../file"
import { Project } from "./project"
import { Bus } from "../bus"
import { Command } from "../command"
import { Instance } from "./instance"
import { Vcs } from "./vcs"
import { Log } from "@/util/log"
import { ShareNext } from "@/share/share-next"
import { Snapshot } from "../snapshot"
import { Truncate } from "../tool/truncation"

export async function InstanceBootstrap() {
  Log.Default.info("bootstrapping", { directory: Instance.directory })

  async function stage<T>(name: string, fn: () => T | Promise<T>): Promise<T> {
    const startedAt = Date.now()
    Log.Default.debug("instance bootstrap stage", { stage: name, status: "started" })
    try {
      const result = await fn()
      Log.Default.debug("instance bootstrap stage", {
        stage: name,
        status: "completed",
        duration: Date.now() - startedAt,
      })
      return result
    } catch (error) {
      Log.Default.error("instance bootstrap stage", {
        stage: name,
        status: "failed",
        duration: Date.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      })
      throw error
    }
  }

  await stage("plugin-init", () => Plugin.init())
  await stage("share-next-init", () => ShareNext.init())
  await stage("format-init", () => Format.init())
  await stage("lsp-init", () => LSP.init())
  await stage("file-watcher-init", () => FileWatcher.init())
  await stage("file-init", () => File.init())
  await stage("vcs-init", () => Vcs.init())
  await stage("snapshot-init", () => Snapshot.init())
  await stage("truncate-init", () => Truncate.init())

  await stage("command-event-subscription", () =>
    Bus.subscribe(Command.Event.Executed, async (payload) => {
      if (payload.properties.name === Command.Default.INIT) {
        await Project.setInitialized(Instance.project.id)
      }
    }),
  )
}
