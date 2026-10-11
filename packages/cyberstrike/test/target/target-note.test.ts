import { expect, test } from "bun:test"
import { redactTargetNoteLine, redactTargetNoteSecrets } from "../../src/target/redact"

test("redacts common secrets before target notes are persisted", () => {
  const source = [
    "Authorization: Bearer abc.def.ghi",
    "Cookie: session=secret-session; refresh=secret-refresh",
    "api_key=secret-api-key",
    '{"password":"secret-password","client_secret":"secret-client"}',
    '{"password":"super secret password","client_secret":"a multi word secret"}',
    "eyJabcdefgh.abcdefgh.abcdefgh",
  ].join("\n")
  const redacted = redactTargetNoteSecrets(source)
  for (const secret of ["abc.def.ghi", "secret-session", "secret-refresh", "secret-api-key", "secret-password", "secret-client", "super secret password", "a multi word secret", "eyJabcdefgh.abcdefgh.abcdefgh"]) {
    expect(redacted).not.toContain(secret)
  }
  expect(redacted).toContain("[REDACTED]")
  expect(redacted).toContain("[JWT REDACTED]")
})


test("sanitizes target metadata into a single Markdown-safe line", () => {
  expect(redactTargetNoteLine("login\n### forged heading\r\n- Source: injected", 180)).toBe("login ### forged heading - Source: injected")
  expect(redactTargetNoteLine("account\t  label", 30)).toBe("account label")
})
