import { describe, expect, test } from "bun:test"
import { parseScopeFileContents } from "./scope-file"

describe("parseScopeFileContents", () => {
  test("parses exact entries and explicit wildcards without broadening", () => {
    expect(parseScopeFileContents("# program scope\r\natt.com\n*.att.com\n192.0.2.0/24\n")).toEqual([
      "att.com",
      "*.att.com",
      "192.0.2.0/24",
    ])
  })

  test("ignores blank lines and full-line comments", () => {
    expect(parseScopeFileContents("\n  # comment\n // comment\napi.att.com  \n")).toEqual(["api.att.com"])
  })

  test("rejects entries containing internal whitespace with the source line number", () => {
    expect(() => parseScopeFileContents("att.com\nnot a host\n")).toThrow("line 2")
  })

  test("rejects files with no usable entries", () => {
    expect(() => parseScopeFileContents("# only comments\n\n// and blanks")).toThrow("no usable entries")
  })
})
