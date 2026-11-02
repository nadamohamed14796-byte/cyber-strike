import { test, expect } from "bun:test"
import { isLoginLikeUrl, isSocialLoginLabel, waitForManualLogin } from "../src/auth.ts"

test("isLoginLikeUrl recognises login route segments and avoids unrelated paths", () => {
  expect(isLoginLikeUrl("https://app.example.test/login")).toBe(true)
  expect(isLoginLikeUrl("https://app.example.test/account/sign-in/step")).toBe(true)
  expect(isLoginLikeUrl("https://app.example.test/profile/authored-posts")).toBe(false)
  expect(isLoginLikeUrl("https://auth.example.test/dashboard")).toBe(false)
  expect(isLoginLikeUrl("not a URL")).toBe(false)
})

test("isSocialLoginLabel blocks social and SSO buttons but allows first-party actions", () => {
  expect(isSocialLoginLabel("Continue with Google")).toBe(true)
  expect(isSocialLoginLabel("Sign in with GitHub")).toBe(true)
  expect(isSocialLoginLabel("Microsoft SSO")).toBe(true)
  expect(isSocialLoginLabel("Continue")).toBe(false)
  expect(isSocialLoginLabel("Sign in")).toBe(false)
})

test("waitForManualLogin rejects on abort and removes its page-load listener", async () => {
  const controller = new AbortController()
  let removed = false
  const page = {
    exposeFunction: async () => {},
    evaluate: async () => {},
    on: () => {},
    removeListener: (event: string) => {
      if (event === "load") removed = true
    },
  } as unknown as Parameters<typeof waitForManualLogin>[0]

  const waiting = waitForManualLogin(page, "abort-test", undefined, controller.signal)
  await new Promise((resolve) => setTimeout(resolve, 0))
  controller.abort()

  await expect(waiting).rejects.toMatchObject({ name: "AbortError" })
  expect(removed).toBe(true)
})

test("waitForManualLogin rejects immediately for an already-aborted signal", async () => {
  const controller = new AbortController()
  controller.abort()
  let exposed = false
  const page = {
    exposeFunction: async () => { exposed = true },
  } as unknown as Parameters<typeof waitForManualLogin>[0]

  await expect(waitForManualLogin(page, "already-aborted", undefined, controller.signal))
    .rejects.toMatchObject({ name: "AbortError" })
  expect(exposed).toBe(false)
})

test("waitForManualLogin still resolves when the operator confirms login", async () => {
  let ready: (() => void) | undefined
  const page = {
    exposeFunction: async (name: string, callback: () => void) => {
      if (name === "__cyberstrikeReady_manual-test") ready = callback
    },
    evaluate: async () => {},
    on: () => {},
    removeListener: () => {},
  } as unknown as Parameters<typeof waitForManualLogin>[0]

  const waiting = waitForManualLogin(page, "manual-test")
  await new Promise((resolve) => setTimeout(resolve, 0))
  ready?.()
  await expect(waiting).resolves.toBeUndefined()
})
