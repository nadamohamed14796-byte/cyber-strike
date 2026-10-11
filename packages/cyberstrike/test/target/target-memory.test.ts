import { describe, expect, test } from "bun:test"
import { TargetMemory } from "../../src/target"

describe("target memory normalization", () => {
  test("normalizes a bare hostname and removes query strings and fragments", () => {
    const target = TargetMemory.normalize("EXAMPLE.com/?token=must-not-be-saved#frag")
    expect(target.targetURL).toBe("https://example.com")
    expect(target.targetKey).toBe("https://example.com")
    expect(target.hostname).toBe("example.com")
    expect(target.slug).toMatch(/^example-com-[a-f0-9]{8}$/)
  })

  test("keeps a normalized path while avoiding sensitive URL parameters", () => {
    const target = TargetMemory.normalize("https://Example.com/Api/v1/?key=secret#section")
    expect(target.targetURL).toBe("https://example.com/Api/v1")
    expect(target.targetKey).toBe("https://example.com/Api/v1")
    expect(target.hostname).toBe("example.com")
  })

  test("separates different target paths on the same host", () => {
    const first = TargetMemory.normalize("https://example.com/app-a")
    const second = TargetMemory.normalize("https://example.com/app-b")
    expect(first.targetKey).not.toBe(second.targetKey)
    expect(first.slug).not.toBe(second.slug)
  })

  test("rejects unsupported schemes and credentials", () => {
    expect(() => TargetMemory.normalize("ftp://example.com")).toThrow()
    expect(() => TargetMemory.normalize("https://user:password@example.com")).toThrow()
  })
})
