import { describe, expect, test } from "bun:test"
import { matchingScopeItems } from "./scope-index"

describe("matchingScopeItems", () => {
  test("matches a listed exact host but does not treat it as a wildcard", () => {
    const entries = ["att.com", "login.att.com"]
    expect(matchingScopeItems("https://att.com/login", entries)).toEqual(["att.com"])
    expect(matchingScopeItems("https://www.att.com/", entries)).toEqual([])
    expect(matchingScopeItems("https://login.att.com/", entries)).toEqual(["login.att.com"])
  })

  test("matches explicit wildcards only on subdomains, including nested wildcard rules", () => {
    const entries = ["*.att.com", "*.api.att.com"]
    expect(matchingScopeItems("https://att.com/", entries)).toEqual([])
    expect(matchingScopeItems("https://www.att.com/", entries)).toEqual(["*.att.com"])
    expect(matchingScopeItems("https://v1.api.att.com/", entries)).toEqual(["*.api.att.com", "*.att.com"])
  })

  test("matches IPv4 CIDRs and refuses addresses outside the range", () => {
    const entries = ["192.0.2.0/24"]
    expect(matchingScopeItems("https://192.0.2.17/", entries)).toEqual(["192.0.2.0/24"])
    expect(matchingScopeItems("https://192.0.3.17/", entries)).toEqual([])
  })

  test("reuses compiled indexes for the same list and recompiles a replacement list", () => {
    const first = ["old.example"]
    expect(matchingScopeItems("https://old.example/", first)).toEqual(["old.example"])
    expect(matchingScopeItems("https://new.example/", first)).toEqual([])

    const replacement = ["new.example"]
    expect(matchingScopeItems("https://new.example/", replacement)).toEqual(["new.example"])
    expect(matchingScopeItems("https://old.example/", replacement)).toEqual([])
  })

  test("keeps exact-host lookups practical for very large scope lists", () => {
    const entries = Array.from({ length: 100_000 }, (_, index) => "host-" + index + ".att.com")
    entries.push("wanted.att.com")
    expect(matchingScopeItems("https://wanted.att.com/", entries)).toEqual(["wanted.att.com"])
    // The second lookup uses the same compiled Set rather than rebuilding it.
    expect(matchingScopeItems("https://missing.att.com/", entries)).toEqual([])
  })
})
