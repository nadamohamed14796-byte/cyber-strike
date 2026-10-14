import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

// Each package test run gets its own XDG roots. The database and caches are
// initialized from xdg-basedir at module import time, so isolation must be set
// in the environment before the Bun test runner starts.
const testHome = await fs.mkdtemp(path.join(os.tmpdir(), "cyberstrike-test-home-"))

await Promise.all(["data", "cache", "config", "state"].map((name) =>
  fs.mkdir(path.join(testHome, name), { recursive: true }),
))

const env = {
  ...process.env,
  CYBERSTRIKE_TEST_HOME: testHome,
  XDG_DATA_HOME: path.join(testHome, "data"),
  XDG_CACHE_HOME: path.join(testHome, "cache"),
  XDG_CONFIG_HOME: path.join(testHome, "config"),
  XDG_STATE_HOME: path.join(testHome, "state"),
}

try {
  const child = Bun.spawn(["bun", "test", "--timeout", "30000"], {
    cwd: process.cwd(),
    env,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  })

  process.exitCode = await child.exited
} finally {
  await fs.rm(testHome, { recursive: true, force: true })
}
