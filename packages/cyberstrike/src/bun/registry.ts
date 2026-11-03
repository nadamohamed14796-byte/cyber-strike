import { readableStreamToText, semver } from "bun"
import { Log } from "../util/log"

export namespace PackageRegistry {
  const log = Log.create({ service: "bun" })

  function which() {
    return process.execPath
  }

  export async function info(pkg: string, field: string, cwd?: string): Promise<string | null> {
    try {
      const result = Bun.spawn([which(), "info", pkg, field], {
        cwd,
        stdout: "pipe",
        stderr: "pipe",
        signal: AbortSignal.timeout(10_000),
        env: {
          ...process.env,
          BUN_BE_BUN: "1",
        },
      })

      // Drain both pipes while the child runs to avoid pipe-buffer deadlocks.
      const stdoutPromise = result.stdout ? readableStreamToText(result.stdout) : Promise.resolve("")
      const stderrPromise = result.stderr ? readableStreamToText(result.stderr) : Promise.resolve("")
      const [code, stdout, stderr] = await Promise.all([result.exited, stdoutPromise, stderrPromise])
      if (code !== 0) {
        log.warn("bun info failed", { pkg, field, code, stderr })
        return null
      }
      const value = stdout.trim()
      return value || null
    } catch (error) {
      // Registry metadata is optional; a stalled registry must not block startup.
      log.warn("bun info timed out or failed; using cached package metadata", { pkg, field, error })
      return null
    }
  }

  export async function isOutdated(pkg: string, cachedVersion: string, cwd?: string): Promise<boolean> {
    // A wildcard accepts every published version; checking the registry on
    // every launch cannot change the decision and only adds startup latency.
    if (cachedVersion.trim() === "*" || cachedVersion.trim().toLowerCase() === "latest") return false
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
