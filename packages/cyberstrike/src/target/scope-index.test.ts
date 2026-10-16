import { describe, expect, test } from "bun:test"
import { matchingScopeItems } from "./scope-index"

describe("matchingScopeItems", () => {
  test("matches a listed exact host but does not treat it as a wildcard", () => {
    const entries = ["att.com", "login.att.com"]
    expect(matchingScopeItems("https://att.com/login", entries)).toEqual(["att.com"])
    expect(matchingScopeItems("https://www.att.com/", entries)).toEqual([])
    expect(matchingScopeItems("https://login.att.com/", entries)).toEqual(["login.att.com"])
  })

  test("matches explicit wildcards on the apex and subdomains, including nested wildcard rules", () => {
    const entries = ["*.att.com", "*.api.att.com"]
    expect(matchingScopeItems("https://att.com/", entries)).toEqual(["*.att.com"])
    expect(matchingScopeItems("https://www.att.com/", entries)).toEqual(["*.att.com"])
    expect(matchingScopeItems("https://api.att.com/", entries)).toEqual(["*.api.att.com", "*.att.com"])
    expect(matchingScopeItems("https://v1.api.att.com/", entries)).toEqual(["*.api.att.com", "*.att.com"])
    expect(matchingScopeItems("https://notatt.com/", entries)).toEqual([])
  })

  test("matches IPv4 CIDRs and refuses addresses outside the range", () => {
    const entries = ["192.0.2.0/24"]
    expect(matchingScopeItems("https://192.0.2.17/", entries)).toEqual(["192.0.2.0/24"])
    expect(matchingScopeItems("https://192.0.3.17/", entries)).toEqual([])
  })

  test("recompiles a replacement list rather than reusing an old index", () => {
    const first = ["old.example"]
    expect(matchingScopeItems("https://old.example/", first)).toEqual(["old.example"])
    expect(matchingScopeItems("https://new.example/", first)).toEqual([])
    const replacement = ["new.example"]
    expect(matchingScopeItems("https://new.example/", replacement)).toEqual(["new.example"])
    expect(matchingScopeItems("https://old.example/", replacement)).toEqual([])
  })

  test("supports large lists and reuses the compiled index for repeated checks", () => {
    const entries = Array.from({ length: 100_000 }, (_, index) => "host-" + index + ".att.com")
    entries.push("wanted.att.com")
    expect(matchingScopeItems("https://wanted.att.com/", entries)).toEqual(["wanted.att.com"])
    expect(matchingScopeItems("https://missing.att.com/", entries)).toEqual([])
  })
})
