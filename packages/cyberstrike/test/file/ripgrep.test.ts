import { describe, expect, test } from "bun:test"
import fs from "fs/promises"
import path from "path"
import { tmpdir } from "../fixture/fixture"
import { Ripgrep } from "../../src/file/ripgrep"
import { File } from "../../src/file"
import { Instance } from "../../src/project/instance"

describe("file.ripgrep", () => {
  test("defaults to include hidden", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "visible.txt"), "hello")
        await fs.mkdir(path.join(dir, ".cyberstrike"), { recursive: true })
        await Bun.write(path.join(dir, ".cyberstrike", "thing.json"), "{}")
      },
    })

    const files = await Array.fromAsync(Ripgrep.files({ cwd: tmp.path }))
    const hasVisible = files.includes("visible.txt")
    const hasHidden = files.includes(path.join(".cyberstrike", "thing.json"))
    expect(hasVisible).toBe(true)
    expect(hasHidden).toBe(true)
  })

  test("hidden false excludes hidden", async () => {
    await using tmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "visible.txt"), "hello")
        await fs.mkdir(path.join(dir, ".cyberstrike"), { recursive: true })
        await Bun.write(path.join(dir, ".cyberstrike", "thing.json"), "{}")
      },
    })

    const files = await Array.fromAsync(Ripgrep.files({ cwd: tmp.path, hidden: false }))
    const hasVisible = files.includes("visible.txt")
    const hasHidden = files.includes(path.join(".cyberstrike", "thing.json"))
    expect(hasVisible).toBe(true)
    expect(hasHidden).toBe(false)
  })
})


test("file search waits for the initial inventory scan and reuses its completed index", async () => {
  await using tmp = await tmpdir()
  const originalFiles = Ripgrep.files
  let startedResolve!: () => void
  const started = new Promise<void>((resolve) => {
    startedResolve = resolve
  })
  let releaseResolve!: () => void
  const released = new Promise<void>((resolve) => {
    releaseResolve = resolve
  })
  let scanCount = 0

  Ripgrep.files = (async function* () {
    scanCount++
    startedResolve()
    await released
    yield path.join("packages", "app", "package.json")
  }) as typeof Ripgrep.files

  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        File.init()
        await started

        let completed = false
        const searching = File.search({
          query: "packages/app/package.json",
          dirs: false,
          limit: 10,
        }).then((results) => {
          completed = true
          return results
        })

        await new Promise((resolve) => setTimeout(resolve, 10))
        expect(completed).toBe(false)

        releaseResolve()
        expect(await searching).toContain(path.join("packages", "app", "package.json"))
        expect(scanCount).toBe(1)
        expect(await File.search({
          query: "packages/app/package.json",
          dirs: false,
          limit: 10,
        })).toContain(path.join("packages", "app", "package.json"))
        expect(scanCount).toBe(1)
        await Instance.dispose()
      },
    })
  } finally {
    releaseResolve()
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        await Instance.dispose()
      },
    }).catch(() => undefined)
    Ripgrep.files = originalFiles
  }
})

test("file inventory aborts and settles before instance disposal completes", async () => {
  await using tmp = await tmpdir()
  const originalFiles = Ripgrep.files
  let startedResolve!: () => void
  const started = new Promise<void>((resolve) => {
    startedResolve = resolve
  })
  let signal: AbortSignal | undefined
  let scanSettled = false

  Ripgrep.files = (async function* (input) {
    signal = input.signal
    startedResolve()
    try {
      await new Promise<void>((resolve) => {
        if (input.signal?.aborted) {
          resolve()
          return
        }
        input.signal?.addEventListener("abort", () => resolve(), { once: true })
      })
    } finally {
      scanSettled = true
    }
  }) as typeof Ripgrep.files

  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        File.init()
        await started
        expect(signal?.aborted).toBe(false)
        await Instance.dispose()
        expect(signal?.aborted).toBe(true)
        expect(scanSettled).toBe(true)
      },
    })
  } finally {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        await Instance.dispose()
      },
    }).catch(() => undefined)
    Ripgrep.files = originalFiles
  }
})

test("file enumeration keeps genuine missing-directory errors visible", async () => {
  await using tmp = await tmpdir()
  const missing = path.join(tmp.path, "missing-directory")
  await expect(Array.fromAsync(Ripgrep.files({ cwd: missing }))).rejects.toMatchObject({
    code: "ENOENT",
    path: missing,
  })
})
