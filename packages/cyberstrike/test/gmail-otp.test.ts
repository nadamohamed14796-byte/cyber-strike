import { describe, expect, test } from "bun:test"
import { extractOtpCode } from "../src/gmail-otp"

describe("Gmail OTP extraction", () => {
  test("extracts a code near verification language", () => {
    expect(extractOtpCode("Your verification code is 482901")).toBe("482901")
  })
  test("does not require the keyword when a six digit code is present", () => {
    expect(extractOtpCode("Use 123456 to continue")).toBe("123456")
  })
  test("returns undefined when no code is present", () => {
    expect(extractOtpCode("Please verify your account using the link")).toBeUndefined()
  })
})
