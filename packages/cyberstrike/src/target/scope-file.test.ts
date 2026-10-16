import { describe, expect, test } from "bun:test"
import { parseScopeFileContents, resolveScopeFilePath } from "./scope-file"

describe("parseScopeFileContents", () => {
  test("parses exact entries and explicit wildcards without broadening", () => {
    expect(parseScopeFileContents("# program scope\r\natt.com\n*.att.com\n192.0.2.0/24\n")).toEqual([
      "att.com",
      "*.att.com",
      "192.0.2.0/24",
    ])
  })

  test("preserves URL path scopes, service ports, and other compact scope identifiers", () => {
    expect(parseScopeFileContents("https://example.com/api/*\\napi.example.com:8443\\ncom.example.mobile\\n2001:db8::1")).toEqual([
      "https://example.com/api/*",
      "api.example.com:8443",
      "com.example.mobile",
      "2001:db8::1",
    ])
  })

  test("ignores blank lines and full-line comments", () => {
    expect(parseScopeFileContents("\n  # comment\n // comment\napi.att.com  \n")).toEqual(["api.att.com"])
  })

  test("accepts a UTF-8 byte-order mark on the first entry", () => {
    expect(parseScopeFileContents("\uFEFFatt.com\napi.att.com")).toEqual(["att.com", "api.att.com"])
  })

  test("rejects entries containing internal whitespace with the source line number", () => {
    expect(() => parseScopeFileContents("att.com\nnot a host\n")).toThrow("line 2")
  })

  test("rejects files with no usable entries", () => {
    expect(() => parseScopeFileContents("# only comments\n\n// and blanks")).toThrow("no usable entries")
  })

  test("converts Windows Explorer WSL UNC paths to the matching Linux path", () => {
    expect(resolveScopeFilePath(String.raw`\\wsl.localhost\kali-linux\root\att.com.txt`, "/repo", "linux"))
      .toBe("/root/att.com.txt")
    expect(resolveScopeFilePath(String.raw`\\wsl$\kali-linux\root\att.com.txt`, "/repo", "linux"))
      .toBe("/root/att.com.txt")
  })

  test("keeps ordinary relative paths under the current working directory", () => {
    expect(resolveScopeFilePath("scope/att.com.txt", "/repo", "linux")).toBe("/repo/scope/att.com.txt")
  })
})
