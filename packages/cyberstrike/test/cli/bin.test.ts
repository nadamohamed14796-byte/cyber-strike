import { expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

test("the npm launcher resolves its own file path under Node ESM", async () => {
  if (process.platform === "win32") return

  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "cyberstrike-bin-esm-"))
  try {
    const packageRoot = path.join(temp, "packages", "cyberstrike")
    const binDir = path.join(packageRoot, "bin")
    await fs.mkdir(binDir, { recursive: true })
    await fs.writeFile(path.join(packageRoot, "package.json"), JSON.stringify({ type: "module" }))
    const sourceLauncher = path.resolve(import.meta.dir, "../../bin/cyberstrike")
    const launcher = path.join(binDir, "cyberstrike")
    await fs.copyFile(sourceLauncher, launcher)

    const packageNames = [
      "@cyberstrike-io/cyberstrike-linux-x64",
      "@cyberstrike-io/cyberstrike-linux-x64-baseline",
      "@cyberstrike-io/cyberstrike-linux-x64-musl",
      "@cyberstrike-io/cyberstrike-linux-x64-baseline-musl",
    ]
    for (const name of packageNames) {
      const fakeBinary = path.join(packageRoot, "node_modules", name, "bin", "cyberstrike")
      await fs.mkdir(path.dirname(fakeBinary), { recursive: true })
      await fs.writeFile(fakeBinary, '#!/bin/sh\nprintf "launcher-ok:%s\\n" "$*"\n')
      await fs.chmod(fakeBinary, 0o755)
    }

    const result = spawnSync("node", [launcher, "--sentinel", "ok"], { encoding: "utf8" })
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    expect(result.stdout).toContain("launcher-ok:--sentinel ok")
  } finally {
    await fs.rm(temp, { recursive: true, force: true })
  }
})
