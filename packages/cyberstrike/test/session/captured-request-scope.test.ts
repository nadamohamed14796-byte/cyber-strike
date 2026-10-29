import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { checkCapturedRequestScope } from "../../src/session/captured-request-scope"
import { tmpdir } from "../fixture/fixture"

test("captured request scope checks the raw concrete path against the persisted manifest", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      await TargetMemory.configureScope("https://program-root.example.test", {
        include: ["https://authorized-app.example.net/safe"],
        authorizationSource: "Captured-request scope fixture",
        userConfirmed: true,
      })

      const allowed = await checkCapturedRequestScope({
        scheme: "https",
        rawRequest: "GET /safe/profile HTTP/1.1\r\nHost: authorized-app.example.net\r\n\r\n",
      })
      expect(allowed.allowed).toBe(true)
      expect(allowed.url).toBe("https://authorized-app.example.net/safe/profile")

      const outOfScopePath = await checkCapturedRequestScope({
        scheme: "https",
        rawRequest: "GET /admin/12345 HTTP/1.1\r\nHost: authorized-app.example.net\r\n\r\n",
      })
      expect(outOfScopePath.allowed).toBe(false)
      expect(outOfScopePath.reason).toBeTruthy()

      const outOfScopeHost = await checkCapturedRequestScope({
        scheme: "https",
        rawRequest: "GET /safe/profile HTTP/1.1\r\nHost: other-app.example.org\r\n\r\n",
      })
      expect(outOfScopeHost.allowed).toBe(false)

      const originSmuggle = await checkCapturedRequestScope({
        scheme: "https",
        rawRequest: "GET https://other-app.example.org/safe/profile HTTP/1.1\r\nHost: authorized-app.example.net\r\n\r\n",
      })
      expect(originSmuggle.allowed).toBe(false)

      const malformed = await checkCapturedRequestScope({
        scheme: "https",
        rawRequest: "not an HTTP request",
      })
      expect(malformed.allowed).toBe(false)
      expect(malformed.reason).toContain("could not be parsed")
    },
  })
})
