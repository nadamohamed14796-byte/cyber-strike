import { describe, expect, test } from "bun:test"
import { shouldRejectUnauthorized } from "../../src/tool/http-replay"

describe("HTTP replay TLS verification", () => {
  test("rejects invalid certificates by default", () => {
    expect(shouldRejectUnauthorized(undefined)).toBe(true)
    expect(shouldRejectUnauthorized(false)).toBe(true)
  })

  test("accepts invalid certificates only with explicit opt-in", () => {
    expect(shouldRejectUnauthorized(true)).toBe(false)
  })
})
