import { describe, expect, test } from "bun:test"
import { isAuthVaultDataValid, normalizeAuthOrigin } from "../src/auth-vault"

describe("normalizeAuthOrigin", () => {
  test("matches only the normalized origin, not a path", () => {
    expect(normalizeAuthOrigin("https://Example.com/login?next=/account")).toBe("https://example.com")
    expect(normalizeAuthOrigin("https://example.com/another/path")).toBe("https://example.com")
  })

  test("preserves non-default ports as part of the origin", () => {
    expect(normalizeAuthOrigin("https://example.com:8443/login")).toBe("https://example.com:8443")
  })

  test("rejects non-http protocols", () => {
    expect(() => normalizeAuthOrigin("file:///tmp/secret")).toThrow("Only http(s) origins")
  })

  test("rejects credentials embedded in a URL", () => {
    expect(() => normalizeAuthOrigin("https://user:pass@example.com")).toThrow("Do not put credentials")
  })
})


describe("AuthVault persisted data validation", () => {
  const validRecord = () => ({
    id: "0123456789abcdef0123456789abcdef",
    origin: "https://example.com",
    purpose: "target",
    account: "research-account",
    username: "tester@example.com",
    targetID: "target_123",
    password: {
      iv: Buffer.alloc(12, 1).toString("base64"),
      tag: Buffer.alloc(16, 2).toString("base64"),
      ciphertext: Buffer.alloc(32, 3).toString("base64"),
    },
    createdAt: 1,
    updatedAt: 2,
  })

  test("accepts an empty vault and a correctly shaped encrypted profile", () => {
    expect(isAuthVaultDataValid([])).toBe(true)
    expect(isAuthVaultDataValid([validRecord()])).toBe(true)
  })

  test("rejects malformed rows instead of trusting an array cast", () => {
    expect(isAuthVaultDataValid([null])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), username: 123 }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), account: "bad\nlabel" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), username: "bad\nname" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), origin: "file:///etc/passwd" }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), targetID: undefined }])).toBe(false)
    expect(isAuthVaultDataValid([{ ...validRecord(), password: { iv: "abc", tag: "bad", ciphertext: "x" } }])).toBe(false)
  })

  test("rejects duplicate profile IDs that would make secret lookup ambiguous", () => {
    const row = validRecord()
    expect(isAuthVaultDataValid([row, { ...row, account: "another-account" }])).toBe(false)
  })
})
