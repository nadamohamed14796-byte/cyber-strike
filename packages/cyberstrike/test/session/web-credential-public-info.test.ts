import { expect, test } from "bun:test"
import { WebCredential } from "../../src/session/web/web-credential"

test("public credential event info never includes reusable secrets", () => {
  const privateCredential = WebCredential.Info.parse({
    id: "cred_test",
    session_id: "ses_test",
    label: "admin",
    headers: {
      Authorization: "Bearer live-access-token",
      Cookie: "session=live-cookie",
      "X-API-Key": "live-api-key",
      "X-Trace-ID": "public-trace-id",
    },
    username: "admin@example.test",
    password: "live-password",
    valid: true,
    recipe: {
      auth_type: "bearer",
      steps: [{ request_id: "req_test", override_body: "password=live-password" }],
      credential_map: { Authorization: "Bearer live-access-token" },
    },
    time: { created: 1, updated: 2 },
  })

  const publicInfo = WebCredential.toPublicInfo(privateCredential)
  expect("password" in publicInfo).toBe(false)
  expect("recipe" in publicInfo).toBe(false)
  expect(publicInfo.headers.Authorization).toBe("[REDACTED]")
  expect(publicInfo.headers.Cookie).toBe("[REDACTED]")
  expect(publicInfo.headers["X-API-Key"]).toBe("[REDACTED]")
  expect(publicInfo.headers["X-Trace-ID"]).toBe("public-trace-id")
})
