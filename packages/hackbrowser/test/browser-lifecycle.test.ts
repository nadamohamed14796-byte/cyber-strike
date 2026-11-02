import { expect, test } from "bun:test"
import { closeBrowserOnSetupFailure } from "../src/browser-lifecycle.ts"

test("closes the browser when context/page setup fails and preserves the setup error", async () => {
  const setupError = new Error("newPage failed")
  let closeCount = 0
  const browser = {
    close: async () => {
      closeCount++
    },
  }

  await expect(closeBrowserOnSetupFailure(browser, async () => {
    throw setupError
  })).rejects.toBe(setupError)

  expect(closeCount).toBe(1)
})

test("does not close the browser when setup succeeds", async () => {
  let closeCount = 0
  const browser = {
    close: async () => {
      closeCount++
    },
  }

  const result = await closeBrowserOnSetupFailure(browser, async () => "ready")

  expect(result).toBe("ready")
  expect(closeCount).toBe(0)
})

test("does not replace the setup error when browser cleanup also fails", async () => {
  const setupError = new Error("addInitScript failed")
  let closeCount = 0
  const browser = {
    close: async () => {
      closeCount++
      throw new Error("browser close failed")
    },
  }

  await expect(closeBrowserOnSetupFailure(browser, async () => {
    throw setupError
  })).rejects.toBe(setupError)

  expect(closeCount).toBe(1)
})
