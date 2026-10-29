import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { checkCapturedRequestScope } from "../../src/session/captured-request-scope"
import { tmpdir } from "../fixture/fixture"

test("captured request scope uses the persisted program manifest before analysis", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      await TargetMemory.configureScope("https://program-root.example.test", {
        include: ["https://authorized-app.example.net"],
        authorizationSource: "Captured-request scope fixture",
        userConfirmed: true,
      })

      const allowed = await checkCapturedRequestScope({
        origin: "https://authorized-app.example.net",
        normalizedPath: "/api/v1/profile",
      })
      expect(allowed.allowed).toBe(true)
      expect(allowed.url).toBe("https://authorized-app.example.net/api/v1/profile")

      const outOfScope = await checkCapturedRequestScope({
        origin: "https://other-app.example.org",
        normalizedPath: "/api/v1/profile",
      })
      expect(outOfScope.allowed).toBe(false)
      expect(outOfScope.reason).toBeTruthy()

      const missingOrigin = await checkCapturedRequestScope({ normalizedPath: "/api/v1/profile" })
      expect(missingOrigin.allowed).toBe(false)
      expect(missingOrigin.reason).toContain("no unambiguous origin")

      const originSmuggle = await checkCapturedRequestScope({
        origin: "https://authorized-app.example.net",
        normalizedPath: "https://other-app.example.org/api/v1/profile",
      })
      expect(originSmuggle.allowed).toBe(false)
      expect(originSmuggle.reason).toContain("changes origin")
    },
  })
})
