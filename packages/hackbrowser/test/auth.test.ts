import { test, expect } from "bun:test"
import { isLoginLikeUrl, isSocialLoginLabel } from "../src/auth.ts"

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
