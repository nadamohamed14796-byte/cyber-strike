import { Log } from "@/util/log"

export namespace State {
  interface Entry {
    state: any
    dispose?: (state: any) => Promise<void>
  }

  const log = Log.create({ service: "state" })
  const recordsByKey = new Map<string, Map<any, Entry>>()

  export function create<S>(root: () => string, init: () => S, dispose?: (state: Awaited<S>) => Promise<void>) {
    return () => {
      const key = root()
      let entries = recordsByKey.get(key)
      if (!entries) {
        entries = new Map<string, Entry>()
        recordsByKey.set(key, entries)
      }
      const exists = entries.get(init)
      if (exists) return exists.state as S
      const state = init()
      entries.set(init, {
        state,
        dispose,
      })
      return state
    }
  }

  export async function reset(init: () => unknown) {
    const tasks: Promise<void>[] = []
    for (const [key, entries] of [...recordsByKey.entries()]) {
      const entry = entries.get(init)
      if (!entry) continue

      // Remove only this initializer's cached value; unrelated project state stays intact.
      entries.delete(init)
      const label = init.name || "anonymous"

      if (entry.dispose) {
        tasks.push(
          Promise.resolve(entry.state)
            .then((value) => entry.dispose!(value))
            .catch((error) => {
              log.error("Error while resetting state:", { error, key, init: label })
            }),
        )
      }

      if (entries.size === 0 && recordsByKey.get(key) === entries) {
        recordsByKey.delete(key)
      } else {
        log.debug("state reset", { key, init: label })
      }
    }
    await Promise.all(tasks)
  }

  export async function dispose(key: string) {
    const entries = recordsByKey.get(key)
    if (!entries) return

    log.info("waiting for state disposal to complete", { key })

    let disposalFinished = false

    setTimeout(() => {
      if (!disposalFinished) {
        log.warn(
          "state disposal is taking an unusually long time - if it does not complete in a reasonable time, please report this as a bug",
          { key },
        )
      }
    }, 10000).unref()

    const tasks: Promise<void>[] = []
    for (const [init, entry] of entries) {
      if (!entry.dispose) continue

      const label = typeof init === "function" ? init.name : String(init)

      const task = Promise.resolve(entry.state)
        .then((state) => entry.dispose!(state))
        .catch((error) => {
          log.error("Error while disposing state:", { error, key, init: label })
        })

      tasks.push(task)
    }
    await Promise.all(tasks)

    entries.clear()
    recordsByKey.delete(key)

    disposalFinished = true
    log.info("state disposal completed", { key })
  }
}
