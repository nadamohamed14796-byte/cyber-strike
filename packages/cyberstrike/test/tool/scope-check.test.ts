import { describe, expect, test } from "bun:test"
import { checkMatch, ScopeCheckTool } from "../../src/tool/scope-check"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { tmpdir } from "../fixture/fixture"

describe("scope_check IPv4 CIDR matching", () => {
  test("matches valid in-range IPv4 addresses and URLs", () => {
    expect(checkMatch("10.20.30.40", "10.20.30.0/24").matches).toBe(true)
    expect(checkMatch("https://10.20.30.40:8443/api/users", "10.20.30.0/24").matches).toBe(true)
  })

  test("rejects IPv4-looking substrings in an external hostname", () => {
    expect(checkMatch("https://10.20.30.40.attacker.example/path", "10.20.30.0/24").matches).toBe(false)
    expect(checkMatch("https://attacker.example/?next=10.20.30.40", "10.20.30.0/24").matches).toBe(false)
  })

  test("rejects out-of-range and malformed IPv4 addresses", () => {
    expect(checkMatch("10.20.31.40", "10.20.30.0/24").matches).toBe(false)
    expect(checkMatch("999.20.30.40", "10.20.30.0/24").matches).toBe(false)
    expect(checkMatch("10.20.300.40", "10.20.30.0/24").matches).toBe(false)
  })

  test("rejects malformed network addresses and prefix lengths", () => {
    expect(checkMatch("10.20.30.40", "10.20.300.0/24").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/33").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/-1").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/24/extra").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/24/").matches).toBe(false)
  })

  test("rejects credential-bearing target URLs", () => {
    expect(checkMatch("http://user:pass@10.20.30.40/path", "10.20.30.0/24").matches).toBe(false)
  })

  test("requires explicit wildcard scope for subdomains", () => {
    expect(checkMatch("https://example.com/v1", "example.com").matches).toBe(true)
    expect(checkMatch("https://api.example.com/v1", "example.com").matches).toBe(false)
    expect(checkMatch("https://example.com.attacker.test/path", "*.example.com").matches).toBe(false)
    expect(checkMatch("https://api.example.com/path", "*.example.com").matches).toBe(true)
    // The explicit wildcard denotes the domain family, including its apex.
    expect(checkMatch("example.com", "*.example.com").matches).toBe(true)
    expect(checkMatch("notexample.com", "*.example.com").matches).toBe(false)
  })
})


describe("scope_check caller-provided patterns are not authorization", () => {
  test("reports a pattern match without claiming the target is authorized", async () => {
    const info = await ScopeCheckTool.init()
    const result = await info.execute(
      { target: "api.example.com", scope_items: ["*.example.com"] },
      {
        sessionID: "ses_scope_informational",
        messageID: "msg_scope_informational",
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => undefined,
        ask: async () => undefined,
      },
    )

    expect(result.title).toContain("authorization unverified")
    expect(result.output).toContain("Authorization: NOT VERIFIED")
    expect(result.metadata.inScope).toBe(false)
    expect(result.metadata.matchesSuppliedScope).toBe(true)
    expect(result.metadata.authorizationVerified).toBe(false)
    expect(result.metadata.scopeMatchOnly).toBe(true)
  })
})

describe("scope_check uses persisted target scope when a workspace is supplied", () => {
  async function execute(target: string, targetURL: string) {
    const info = await ScopeCheckTool.init()
    return info.execute(
      { target, target_url: targetURL },
      {
        sessionID: "ses_scope_test",
        messageID: "msg_scope_test",
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => undefined,
        ask: async () => undefined,
      },
    )
  }

  test("fails closed for unconfigured scope and honors exclusions over inclusions", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        await TargetMemory.ensure("https://example.com")
        const unconfigured = await execute("api.example.com", "https://example.com")
        expect(unconfigured.metadata.inScope).toBe(false)
        expect(unconfigured.metadata.scopeConfigured).toBe(false)

        await TargetMemory.configureScope("https://example.com", {
          include: ["*.example.com", "example.com"],
          exclude: ["admin.example.com"],
          authorizationSource: "test program",
          authorizationReference: "https://hackerone.com/example",
        })
        const allowed = await execute("api.example.com", "https://example.com")
        expect(allowed.metadata.inScope).toBe(true)
        expect(allowed.metadata.scopeConfigured).toBe(true)

        const excluded = await execute("admin.example.com", "https://example.com")
        expect(excluded.metadata.inScope).toBe(false)
        expect(excluded.metadata.excluded).toBe(true)
        await Instance.dispose()
      },
    })
  })
})
