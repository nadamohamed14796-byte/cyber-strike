import { describe, expect, test } from "bun:test"
import { extractOtpCode } from "../src/gmail-otp"
import { isAllowedSiteSender } from "../src/gmail-service"

describe("Gmail OTP extraction", () => {
  test("extracts a code near verification language", () => {
    expect(extractOtpCode("Your verification code is 482901")).toBe("482901")
  })
  test("extracts a six digit code without keyword", () => {
    expect(extractOtpCode("Use 123456 to continue")).toBe("123456")
  })
  test("returns undefined when no code is present", () => {
    expect(extractOtpCode("Please verify your account using the link")).toBeUndefined()
  })
})

describe("Gmail OTP sender scope", () => {
  test("accepts exact hostname and subdomains", () => {
    expect(isAllowedSiteSender("Example <no-reply@app.example.com>", "https://example.com/login")).toBe(true)
    expect(isAllowedSiteSender("no-reply@example.com", "https://www.example.com")).toBe(true)
  })
  test("rejects lookalike and third-party sender domains", () => {
    expect(isAllowedSiteSender("no-reply@notexample.com", "https://example.com")).toBe(false)
    expect(isAllowedSiteSender("no-reply@mail-provider.net", "https://example.com")).toBe(false)
  })
  test("rejects non-http site URLs", () => {
    expect(() => isAllowedSiteSender("no-reply@example.com", "file:///tmp/a")).toThrow()
  })
})
