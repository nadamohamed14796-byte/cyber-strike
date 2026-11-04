import { describe, expect, test } from "bun:test"
import fs from "fs/promises"
import path from "path"
import { tmpdir } from "../fixture/fixture"
import { Ripgrep } from "../../src/file/ripgrep"
import { File } from "../../src/file"
import { Bus } from "../../src/bus"
import { FileWatcher } from "../../src/file/watcher"
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

test("file search rebuilds its index after edited and watched file events", async () => {
  await using tmp = await tmpdir({
    init: async (dir) => {
      await Bun.write(path.join(dir, "before.js"), "before")
    },
  })
  const originalFiles = Ripgrep.files
  let scanCount = 0
  Ripgrep.files = (async function* (input) {
    scanCount++
    yield* originalFiles(input)
  }) as typeof Ripgrep.files

  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        File.init()
        expect(await File.search({ query: "before.js", dirs: false, limit: 10 })).toContain("before.js")
        expect(scanCount).toBe(1)
        const editedPath = path.join(tmp.path, "edited.js")
        await Bun.write(editedPath, "edited")
        // Internal edit tools publish both events for one logical file change.
        await Bus.publish(File.Event.Edited, { file: editedPath })
        await Bus.publish(FileWatcher.Event.Updated, { file: editedPath, event: "add" })
        expect(await File.search({ query: "edited.js", dirs: false, limit: 10 })).toContain("edited.js")
        expect(scanCount).toBe(2)
        const watchedPath = path.join(tmp.path, "watched.js")
        await Bun.write(watchedPath, "watched")
        await Bus.publish(FileWatcher.Event.Updated, { file: watchedPath, event: "add" })
        expect(await File.search({ query: "watched.js", dirs: false, limit: 10 })).toContain("watched.js")
        expect(scanCount).toBe(3)
        await Instance.dispose()
      },
    })
  } finally {
    await Instance.provide({ directory: tmp.path, fn: () => Instance.dispose() }).catch(() => undefined)
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

test("file search prioritizes slash-normalized nested paths before fuzzy matches", async () => {
  await using tmp = await tmpdir()
  const originalFiles = Ripgrep.files
  const target = path.join("packages", "app", "package.json")
  const query = target.split(path.sep).join("\\")

  Ripgrep.files = (async function* () {
    for (let index = 0; index < 150; index++) {
      yield path.join("packages", "app-copy-" + index, "package.json")
    }
    yield target
  }) as typeof Ripgrep.files

  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        File.init()
        const results = await File.search({ query, dirs: true, limit: 5 })
        expect(results[0]).toBe(target)
        expect(results).toContain(target)
        await Instance.dispose()
      },
    })
  } finally {
    await Instance.provide({
      directory: tmp.path,
      fn: () => Instance.dispose(),
    }).catch(() => undefined)
    Ripgrep.files = originalFiles
  }
})

test("failed instance initialization disposes partial state and can be retried", async () => {
  await using tmp = await tmpdir()
  let disposed = false

  await expect(
    Instance.provide({
      directory: tmp.path,
      init: async () => {
        const state = Instance.state(
          () => ({ active: true }),
          async () => {
            disposed = true
          },
        )
        state()
        throw new Error("bootstrap failed")
      },
      fn: () => undefined,
    }),
  ).rejects.toThrow("bootstrap failed")

  expect(disposed).toBe(true)

  const result = await Instance.provide({
    directory: tmp.path,
    fn: () => "recovered",
  })
  expect(result).toBe("recovered")

  await Instance.provide({
    directory: tmp.path,
    fn: () => Instance.dispose(),
  })
})
