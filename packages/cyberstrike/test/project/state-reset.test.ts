import { expect, test } from "bun:test"
import { State } from "../../src/project/state"

test("resets one cached state while preserving unrelated state for the same project", async () => {
  const key = `state-reset-test-${crypto.randomUUID()}`
  let initialized = 0
  let disposed = 0
  const init = () => ({ value: ++initialized })
  const initUnrelated = () => ({ unrelated: true })
  const getState = State.create(() => key, init, async () => {
    disposed++
  })
  const getUnrelated = State.create(() => key, initUnrelated)

  try {
    const first = getState()
    const unrelated = getUnrelated()
    expect(getState()).toBe(first)

    await State.reset(init)

    const refreshed = getState()
    expect(refreshed).not.toBe(first)
    expect(refreshed.value).toBe(2)
    expect(disposed).toBe(1)
    expect(getUnrelated()).toBe(unrelated)
  } finally {
    await State.dispose(key)
  }
})
