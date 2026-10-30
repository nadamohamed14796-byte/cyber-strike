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
        try {
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

        await info.execute({ action: "init", target_url: "https://example.com" }, ctx as never)
        const configured = await info.execute({
          action: "configure_scope",
          target_url: "https://example.com",
          include: ["example.com", "*.example.com", "https://api.example.net/v2/*"],
          exclude: ["admin.example.com"],
          user_confirmed_scope_list: true,
        }, ctx as never)

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

        // A child asset workspace must not compete with the program root for an
        // explicitly included, unrelated domain. The root owns program-wide scope;
        // child workspaces only own their exact host and DNS subtree.
        const program = await TargetMemory.configureScope("https://program-root.example.test", {
          include: ["api.mercadopago.com", "*.program-root.example.test"],
          authorizationSource: "Program root scope fixture",
          authorizationReference: "https://program.example.test/policy",
        })
        const child = await TargetMemory.attachAsset(program.workspace.targetURL, "https://app.program-root.example.test")
        await TargetMemory.configureScope(child.asset.targetURL, {
          include: ["api.mercadopago.com", "*.program-root.example.test"],
          authorizationSource: "Child scope fixture",
          authorizationReference: "https://program.example.test/policy",
        })
        const unrelatedDecision = await TargetMemory.checkURLScope("https://api.mercadopago.com/")
        expect(unrelatedDecision.allowed).toBe(true)
        expect(unrelatedDecision.workspace?.id).toBe(program.workspace.id)

        // Replacing the include list must not silently erase saved exclusions.
        const replaced = await info.execute({
          action: "configure_scope",
          target_url: "https://example.com",
          include: ["*.example.com", "*.new.example"],
          user_confirmed_scope_list: true,
        }, ctx as never)
        expect(replaced.metadata.saved).toBe(true)
        const replacedScope = await TargetMemory.getScope("https://example.com")
        expect(replacedScope?.scopeItems).toEqual(["*.example.com", "*.new.example"])
        expect(replacedScope?.excludedItems).toEqual(["admin.example.com"])
        expect((await TargetMemory.checkURLScope("https://admin.example.com/")).allowed).toBe(false)
        expect((await TargetMemory.checkURLScope("https://api.new.example/")).allowed).toBe(true)
        } finally {
          await Instance.dispose()
        }
      },
    })
  })

  test("rejects a wildcard configure_scope target instead of creating a second workspace", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        try {
          const info = await TargetWorkspaceTool.init()
          const result = await info.execute({
            action: "configure_scope",
            target_url: "https://*.example.test",
            include: ["*.example.test"],
            user_confirmed_scope_list: true,
          }, {
            sessionID: "ses_wildcard_configure_test",
            messageID: "msg_wildcard_configure_test",
            agent: "cyberstrike",
            abort: new AbortController().signal,
            messages: [],
            metadata: () => undefined,
            ask: async () => undefined,
          } as never)

          expect(result.metadata.saved).toBe(false)
          expect(result.metadata.reason).toBe("wildcard_workspace_identity_rejected")
          expect(result.output).toContain('include: ["*.example.com"]')
          expect(result.output).toContain("user_confirmed_scope_list=true")
          expect(TargetMemory.list()).toHaveLength(0)
        } finally {
          await Instance.dispose()
        }
      },
    })
  })

  test("configure_scope on an authorized subdomain updates its canonical root", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        try {
          const root = await TargetMemory.configureScope("https://www.example.test", {
            include: ["*.example.test"],
            authorizationSource: "Program wildcard scope fixture",
            authorizationReference: "https://program.example.test/policy",
          })
          const info = await TargetWorkspaceTool.init()
          const result = await info.execute({
            action: "configure_scope",
            target_url: "https://app.example.test",
            include: ["api.example.test"],
            merge_existing: true,
          }, {
            sessionID: "ses_subdomain_scope_update_test",
            messageID: "msg_subdomain_scope_update_test",
            agent: "cyberstrike",
            abort: new AbortController().signal,
            messages: [],
            metadata: () => undefined,
            ask: async () => undefined,
          } as never)

          expect(result.metadata.saved).toBe(true)
          expect(result.output).toContain("Target: " + root.workspace.targetURL)
          expect(TargetMemory.list().map((item) => item.targetURL)).toEqual([root.workspace.targetURL])
          expect((await TargetMemory.getScope(root.workspace.targetURL))?.scopeItems).toContain("api.example.test")
        } finally {
          await Instance.dispose()
        }
      },
    })
  })

  test("configure_scope updates the canonical wildcard root instead of a legacy exact-host root", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        try {
          const wildcard = await TargetMemory.configureScope("https://*.example.test", {
            include: ["*.example.test"],
            authorizationSource: "Program wildcard scope fixture",
            authorizationReference: "https://program.example.test/policy",
          })
          const legacy = await TargetMemory.configureScope("https://www.example.test", {
            include: ["www.example.test"],
            authorizationSource: "Legacy exact-host root fixture",
            authorizationReference: "https://program.example.test/policy",
          })

          const info = await TargetWorkspaceTool.init()
          const ctx = {
            sessionID: "ses_configure_canonical_root_test",
            messageID: "msg_configure_canonical_root_test",
            agent: "cyberstrike",
            abort: new AbortController().signal,
            messages: [],
            metadata: () => undefined,
            ask: async () => undefined,
          }
          const result = await info.execute({
            action: "configure_scope",
            target_url: "https://www.example.test",
            include: ["api.example.test"],
            merge_existing: true,
          }, ctx as never)

          expect(result.metadata.saved).toBe(true)
          expect(result.output).toContain("Target: " + wildcard.workspace.targetURL)
          expect((await TargetMemory.getScope(wildcard.workspace.targetURL))?.scopeItems)
            .toContain("api.example.test")
          // Preserve the legacy ledger and its old evidence; only new writes move
          // to the canonical root. No existing workspace is destructively deleted.
          expect((await TargetMemory.getScope(legacy.workspace.targetURL))?.scopeItems)
            .toEqual(["www.example.test"])
          const appDecision = await TargetMemory.checkURLScope("https://app.example.test")
          expect(appDecision.allowed).toBe(true)
          expect(appDecision.workspace?.id).toBe(wildcard.workspace.id)

          const showWithoutTarget = await info.execute({ action: "show" }, ctx as never)
          expect(showWithoutTarget.title).toContain("Target workspaces")
        } finally {
          await Instance.dispose()
        }
      },
    })
  })

  test("init reuses the wildcard canonical root when a legacy exact-host root also exists", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        try {
          const wildcard = await TargetMemory.configureScope("https://*.example.test", {
            include: ["*.example.test"],
            authorizationSource: "Program wildcard scope fixture",
            authorizationReference: "https://program.example.test/policy",
          })
          await TargetMemory.configureScope("https://www.example.test", {
            include: ["www.example.test"],
            authorizationSource: "Legacy exact-host root fixture",
            authorizationReference: "https://program.example.test/policy",
          })

          const info = await TargetWorkspaceTool.init()
          const result = await info.execute({
            action: "init",
            target_url: "https://www.example.test",
          }, {
            sessionID: "ses_canonical_root_reuse_test",
            messageID: "msg_canonical_root_reuse_test",
            agent: "cyberstrike",
            abort: new AbortController().signal,
            messages: [],
            metadata: () => undefined,
            ask: async () => undefined,
          } as never)

          expect(result.metadata.initialized).toBe(true)
          expect(result.output).toContain("Target: " + wildcard.workspace.targetURL)
          expect(result.output).toContain("Workspace: " + wildcard.workspace.workspacePath)
          expect(TargetMemory.list()).toHaveLength(2)
        } finally {
          await Instance.dispose()
        }
      },
    })
  })

})
