import { expect, test } from "bun:test"
import { hasOpenIngressIndicator } from "../../src/tool/iachook"
import { hasSessionLikeCookieHeader } from "../../src/tool/web-recon/programs"

test("open-ingress matching uses token boundaries for any and wildcard values", () => {
  expect(hasOpenIngressIndicator('cidr_blocks = ["0.0.0.0/0"]')).toBe(true)
  expect(hasOpenIngressIndicator('source = "ANY"')).toBe(true)
  expect(hasOpenIngressIndicator('address_prefixes = ["*"]')).toBe(true)
  expect(hasOpenIngressIndicator('description = "company network"')).toBe(false)
  expect(hasOpenIngressIndicator('description = "many internal users"')).toBe(false)
})

test("session-cookie classification examines names rather than generic values", () => {
  expect(hasSessionLikeCookieHeader("session_id=abc123; Path=/; HttpOnly")).toBe(true)
  expect(hasSessionLikeCookieHeader("__Host-access_token=abc123; Path=/; Secure")).toBe(true)
  expect(hasSessionLikeCookieHeader("connect.sid=abc123; Path=/; HttpOnly")).toBe(true)
  expect(hasSessionLikeCookieHeader("analytics_id=authentication-is-configured; Path=/; Secure")).toBe(false)
  expect(hasSessionLikeCookieHeader("theme=tokenized; Path=/; Secure")).toBe(false)
})
