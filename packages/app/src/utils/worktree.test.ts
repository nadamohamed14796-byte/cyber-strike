import { describe, expect, test } from "bun:test"
import { Worktree } from "./worktree"

const dir = (name: string) => `/tmp/cyberstrike-worktree-${name}-${crypto.randomUUID()}`

describe("Worktree", () => {
  test("normalizes trailing slashes", () => {
    const key = dir("normalize")
    Worktree.ready(`${key}/`)

    expect(Worktree.get(key)).toEqual({ status: "ready" })
  })

  test("pending does not overwrite a terminal state", () => {
    const key = dir("pending")
    Worktree.failed(key, "boom")
    expect(Worktree.pending(key)).toBe(false)

    expect(Worktree.get(key)).toEqual({ status: "failed", message: "boom" })
  })

  test("pending reports a ready event that arrived before the create response", () => {
    const key = dir("ready-before-create-response")
    Worktree.ready(key)

    expect(Worktree.pending(key)).toBe(false)
    expect(Worktree.get(key)).toEqual({ status: "ready" })
  })

  test("pending starts a new worktree lifecycle when no terminal event exists", () => {
    const key = dir("pending-active")

    expect(Worktree.pending(key)).toBe(true)
    expect(Worktree.pending(`${key}/`)).toBe(true)
    expect(Worktree.get(key)).toEqual({ status: "pending" })
  })

  test("wait resolves shared pending waiter when ready", async () => {
    const key = dir("wait-ready")
    Worktree.pending(key)

    const a = Worktree.wait(key)
    const b = Worktree.wait(`${key}/`)

    expect(a).toBe(b)

    Worktree.ready(key)

    expect(await a).toEqual({ status: "ready" })
    expect(await b).toEqual({ status: "ready" })
  })

  test("wait resolves with failure message", async () => {
    const key = dir("wait-failed")
    const waiting = Worktree.wait(key)

    Worktree.failed(key, "permission denied")

    expect(await waiting).toEqual({ status: "failed", message: "permission denied" })
    expect(await Worktree.wait(key)).toEqual({ status: "failed", message: "permission denied" })
  })
})
