import { describe, expect, test } from "bun:test"
import { autoLogin } from "../../hackbrowser/src/auth"

describe("saved login origin guard", () => {
  test("refuses to autofill when the browser is on a different origin", async () => {
    const page = { url: () => "https://attacker.example/login" } as unknown as Parameters<typeof autoLogin>[0]
    await expect(autoLogin(page, {
      username: "research-account",
      password: "",
      origin: "https://target.example",
    })).resolves.toEqual({ success: false, error: "saved_login_origin_mismatch" })
  })
})
