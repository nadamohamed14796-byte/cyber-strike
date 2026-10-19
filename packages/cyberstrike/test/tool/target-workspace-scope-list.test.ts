import { describe, expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { TargetWorkspaceTool } from "../../src/tool/target-workspace"
import { tmpdir } from "../fixture/fixture"

describe("target_workspace explicitly confirmed complete scope lists", () => {
  test("accepts one complete list, keeps explicit entries, and preserves exclusions without a fabricated policy URL", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const info = await TargetWorkspaceTool.init()
        const ctx = {
          sessionID: "ses_scope_list_test",
          messageID: "msg_scope_list_test",
          agent: "cyberstrike",
          abort: new AbortController().signal,
          messages: [],
          metadata: () => undefined,
          ask: async () => undefined,
        }

        await info.execute({ action: "init", target_url: "https://example.com" }, ctx)
        const configured = await info.execute({
          action: "configure_scope",
          target_url: "https://example.com",
          include: ["example.com", "*.example.com", "https://api.example.net/v2/*"],
          exclude: ["admin.example.com"],
          user_confirmed_scope_list: true,
        }, ctx)

        expect(configured.metadata.saved).toBe(true)
        expect(configured.metadata.scope_configured).toBe(true)
        const scope = await TargetMemory.getScope("https://example.com")
        expect(scope?.status).toBe("configured")
        expect(scope?.scopeItems).toEqual(["example.com", "*.example.com", "https://api.example.net/v2/*"])
        expect(scope?.excludedItems).toEqual(["admin.example.com"])
        expect(scope?.authorizationReference).toBeNull()
        expect(scope?.authorizationSource).toContain("complete scope list")
        expect((await TargetMemory.checkURLScope("https://api.example.com/")).allowed).toBe(true)
        expect((await TargetMemory.checkURLScope("https://admin.example.com/")).allowed).toBe(false)

        await Instance.dispose()
      },
    })
  })
})
