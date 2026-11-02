import { describe, expect, test } from "bun:test"
import { Scheduler } from "../src/scheduler"
import { Instance } from "../src/project/instance"
import { tmpdir } from "./fixture/fixture"

describe("Scheduler.register", () => {
  const hour = 60 * 60 * 1000

  test("defaults to instance scope per directory", async () => {
    await using one = await tmpdir({ git: true })
    await using two = await tmpdir({ git: true })
    const runs = { count: 0 }
    const id = "scheduler.instance." + Math.random().toString(36).slice(2)
    const task = {
      id,
      interval: hour,
      run: async () => {
        runs.count += 1
      },
    }

    await Instance.provide({
      directory: one.path,
      fn: async () => {
        Scheduler.register(task)
        await Instance.dispose()
      },
    })
    expect(runs.count).toBe(1)

    await Instance.provide({
      directory: two.path,
      fn: async () => {
        Scheduler.register(task)
        await Instance.dispose()
      },
    })
    expect(runs.count).toBe(2)
  })

  test("global scope runs once across instances", async () => {
    await using one = await tmpdir({ git: true })
    await using two = await tmpdir({ git: true })
    const runs = { count: 0 }
    const id = "scheduler.global." + Math.random().toString(36).slice(2)
    const task = {
      id,
      interval: hour,
      run: async () => {
        runs.count += 1
      },
      scope: "global" as const,
    }

    await Instance.provide({
      directory: one.path,
      fn: async () => {
        Scheduler.register(task)
        await Instance.dispose()
      },
    })
    expect(runs.count).toBe(1)

    await Instance.provide({
      directory: two.path,
      fn: async () => {
        Scheduler.register(task)
        await Instance.dispose()
      },
    })
    expect(runs.count).toBe(1)
  })

  test("does not overlap a slow run when the interval is shorter than the task", async () => {
    await using tmp = await tmpdir({ git: true })
    const runs = { count: 0 }
    const active = { count: 0, max: 0 }
    const id = "scheduler.overlap." + Math.random().toString(36).slice(2)

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        Scheduler.register({
          id,
          interval: 2,
          run: async () => {
            runs.count++
            active.count++
            active.max = Math.max(active.max, active.count)
            await new Promise<void>((resolve) => setTimeout(resolve, 20))
            active.count--
          },
        })

        await new Promise<void>((resolve) => setTimeout(resolve, 85))
        expect(runs.count).toBeGreaterThan(1)
        expect(active.max).toBe(1)
        await Instance.dispose()
      },
    })
  })
})
