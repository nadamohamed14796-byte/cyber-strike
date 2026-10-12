import { expect, test } from "bun:test"
import { Network } from "../../src/network/network"

test("proxy host matching includes the base and true subdomains only", () => {
  expect(Network.matchHost("*.example.com", "example.com")).toBe(true)
  expect(Network.matchHost("*.example.com", "api.example.com")).toBe(true)
  expect(Network.matchHost("*.example.com", "notexample.com")).toBe(false)
  expect(Network.matchHost("*example.com", "notexample.com")).toBe(false)
})

test("loopback is bypassed by default but can be explicitly included", () => {
  expect(Network.isBypassed("localhost")).toBe(true)
  expect(Network.isBypassed("127.0.0.8")).toBe(true)
  expect(Network.isBypassed("app.example.com")).toBe(false)
  expect(Network.isBypassed("127.0.0.1", [], true)).toBe(false)
})

test("TLS verification is strict by default and insecure only by explicit opt-in", () => {
  expect(Network.rejectUnauthorized(undefined, {})).toBe(true)
  expect(Network.rejectUnauthorized(false, {})).toBe(true)
  expect(Network.rejectUnauthorized(true, {})).toBe(false)
  expect(Network.rejectUnauthorized(undefined, { rejectUnauthorized: false })).toBe(false)
  expect(Network.rejectUnauthorized(undefined, { rejectUnauthorized: true })).toBe(true)
})

test("proxy credentials are URL-encoded exactly once", () => {
  const value = Network.toProxyUrl("http://127.0.0.1:8080", "user name", "p@ss%word")
  const parsed = new URL(value)
  expect(parsed.username).toBe("user%20name")
  expect(parsed.password).toBe("p%40ss%25word")
})

test("proxy URLs reject embedded credentials and unsupported SOCKS protocols", () => {
  expect(() => Network.toProxyUrl("http://alice:secret@127.0.0.1:8080")).toThrow("Do not embed proxy credentials")
  expect(() => Network.toProxyUrl("socks5://127.0.0.1:1080")).toThrow("HTTP(S)")
})
