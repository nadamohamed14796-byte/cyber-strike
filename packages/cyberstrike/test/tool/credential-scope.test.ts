import { describe, expect, test } from "bun:test"
import { credentialForSession } from "../../src/session/web/credential-scope"

describe("credentialForSession", () => {
  const firstSession = { id: "credential-1", session_id: "session-a", headers: { authorization: "Bearer secret" } }

  test("allows a credential owned by the active session", () => {
    expect(credentialForSession(firstSession, "session-a")).toBe(firstSession)
  })

  test("rejects a credential owned by another session", () => {
    expect(credentialForSession(firstSession, "session-b")).toBeUndefined()
  })

  test("rejects missing credentials and an empty session ID", () => {
    expect(credentialForSession(undefined, "session-a")).toBeUndefined()
    expect(credentialForSession(firstSession, "")).toBeUndefined()
  })
})
