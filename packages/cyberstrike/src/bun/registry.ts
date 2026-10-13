import { readableStreamToText, semver } from "bun"
import { Log } from "../util/log"

export namespace PackageRegistry {
  const log = Log.create({ service: "bun" })

  function which() {
    return process.execPath
  }

  export async function info(pkg: string, field: string, cwd?: string): Promise<string | null> {
    const result = Bun.spawn([which(), "info", pkg, field], {
      cwd,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        BUN_BE_BUN: "1",
      },
    })

    // Consume piped output concurrently with process execution. If we await
    // exit first, a noisy child can fill a pipe buffer and never exit.
    const stdoutPromise = result.stdout ? readableStreamToText(result.stdout) : Promise.resolve("")
    const stderrPromise = result.stderr ? readableStreamToText(result.stderr) : Promise.resolve("")
    const [code, stdout, stderr] = await Promise.all([result.exited, stdoutPromise, stderrPromise])

    if (code !== 0) {
      log.warn("bun info failed", { pkg, field, code, stderr })
      return null
    }

    const value = stdout.trim()
    if (!value) return null
    return value
  }

  export async function isOutdated(pkg: string, cachedVersion: string, cwd?: string): Promise<boolean> {
    const latestVersion = await info(pkg, "version", cwd)
    if (!latestVersion) {
      log.warn("Failed to resolve latest version, using cached", { pkg, cachedVersion })
      return false
    }

    const isRange = /[\s^~*xX<>|=]/.test(cachedVersion)
    if (isRange) return !semver.satisfies(latestVersion, cachedVersion)

    return semver.order(cachedVersion, latestVersion) === -1
  }
}
