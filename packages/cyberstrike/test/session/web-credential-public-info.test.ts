import { expect, test } from "bun:test"
import { WebCredential } from "../../src/session/web/web-credential"

test("public credential info redacts reusable auth headers but keeps harmless metadata", () => {
  const credential = WebCredential.Info.parse({
    id: "cred_public_test",
    session_id: "ses_public_test",
    label: "test-admin",
    headers: {
      Authorization: "Bearer token-must-not-leak",
      Cookie: "session=secret-cookie",
      "X-API-Key": "secret-api-key",
      "X-Trace-ID": "trace-public",
      "X-Custom-Session": "secret-custom-session",
      "X-Custom-Signature": "secret-signature",
    },
    time: { created: 1, updated: 2 },
  })

  const safe = WebCredential.toPublicInfo(credential)
  expect(safe.headers.Authorization).toBe("[REDACTED]")
  expect(safe.headers.Cookie).toBe("[REDACTED]")
  expect(safe.headers["X-API-Key"]).toBe("[REDACTED]")
  expect(safe.headers["X-Custom-Session"]).toBe("[REDACTED]")
  expect(safe.headers["X-Custom-Signature"]).toBe("[REDACTED]")
  expect(safe.headers["X-Trace-ID"]).toBe("trace-public")
  expect(JSON.stringify(safe)).not.toContain("token-must-not-leak")
  expect(JSON.stringify(safe)).not.toContain("secret-cookie")
  expect(JSON.stringify(safe)).not.toContain("secret-api-key")
})

test("credential update event schema accepts the sanitized public shape", () => {
  const credential = WebCredential.Info.parse({
    id: "cred_event_test",
    session_id: "ses_event_test",
    label: "member",
    headers: { Authorization: "Bearer reusable-token" },
    time: { created: 1, updated: 1 },
  })
  const safe = WebCredential.toPublicInfo(credential)
  const event = WebCredential.Event.Updated.payload.parse({
    sessionID: "ses_event_test",
    credentials: [safe],
  })
  expect(event.credentials[0].headers.Authorization).toBe("[REDACTED]")
})
