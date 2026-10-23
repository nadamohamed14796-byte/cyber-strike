import { describe, expect, test } from "bun:test"
import path from "path"
import { BashTool, findWrappedScanner, katanaScopeBlockReason, passiveResearchLookup, reconScannerInvocationKey, scannerLaunchedByWrapper, scannerTargets } from "../../src/tool/bash"
import type { TargetScope } from "../../src/target"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"
import type { PermissionNext } from "../../src/permission/next"
import { Truncate } from "../../src/tool/truncation"

const ctx = {
  sessionID: "test",
  messageID: "",
  callID: "",
  agent: "build",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => {},
  ask: async () => {},
}

const projectRoot = path.join(__dirname, "../..")

describe("tool.bash", () => {
  test("basic", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const bash = await BashTool.init()
        const result = await bash.execute(
          {
            command: "echo 'test'",
            description: "Echo test message",
          },
          ctx,
        )
        expect(result.metadata.exit).toBe(0)
        expect(result.metadata.output).toContain("test")
      },
    })
  })
})

describe("Scanner shell-wrapper detection", () => {
  test("finds nested scanner commands without matching quoted argument text", async () => {
    expect(await findWrappedScanner("cd /tmp && katana -u https://example.com")).toBe("katana")
    expect(await findWrappedScanner("sudo bash -lc 'katana -u https://example.com'")).toBe("katana")
    expect(await findWrappedScanner("xargs -I{} katana -u https://example.com")).toBe("katana")
    expect(await findWrappedScanner("find /tmp -exec katana -u https://example.com \\;")).toBe("katana")
    expect(await findWrappedScanner("bash -lc 'xargs -I{} katana -u https://example.com'")).toBe("katana")
    expect(await findWrappedScanner("bash -lc 'find /tmp -exec env FOO=bar katana -u https://example.com \\;'")).toBe("katana")
    expect(await findWrappedScanner("printf '%s' 'katana -u https://example.com'")).toBeUndefined()
    expect(await findWrappedScanner("grep katana notes.txt")).toBeUndefined()
  })
})

describe("Scope-aware URL source input extraction", () => {
  test("extracts literal waybackurls pipeline hostnames for persisted scope checks", () => {
    expect(scannerTargets(
      ["waybackurls"],
      "printf '%s\\n' 'example.com' | waybackurls",
    )).toContain("https://example.com")
    expect(scannerTargets(
      ["waybackurls"],
      "printf '%s\\n' 'example.com' 'api.example.com' | waybackurls",
    )).toEqual(expect.arrayContaining(["https://example.com", "https://api.example.com"]))
  })

  test("does not infer a target from a file name when a source reads a list from disk", () => {
    expect(scannerTargets(["waybackurls"], "cat domains.txt | waybackurls")).toEqual([])
  })
})

describe("Read-only passive-research API scope routing", () => {
  test("routes recognized CT, passive-DNS, and archive lookups to the queried target domain", () => {
    expect(passiveResearchLookup(new URL("https://crt.sh/?q=%25.example.com&output=json"), ["-s"])).toEqual({
      targetURL: "https://example.com/",
      phase: "asset_discovery",
    })
    expect(passiveResearchLookup(new URL("https://api.certspotter.com/v1/issuances?domain=api.example.com"), ["--silent"])).toEqual({
      targetURL: "https://api.example.com/",
      phase: "asset_discovery",
    })
    expect(passiveResearchLookup(new URL("https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"), ["-s"])).toEqual({
      targetURL: "https://example.com/",
      phase: "asset_discovery",
    })
    expect(passiveResearchLookup(new URL("https://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=json"), ["-s"])).toEqual({
      targetURL: "https://example.com/",
      phase: "url_collection",
    })
  })

  test("does not treat writes, redirects, credentials, secrets, or unknown routes as passive lookups", () => {
    const url = new URL("https://crt.sh/?q=%25.example.com&output=json")
    expect(passiveResearchLookup(url, ["-X", "POST"])).toBeUndefined()
    expect(passiveResearchLookup(url, ["--data", "domain=example.com"])).toBeUndefined()
    expect(passiveResearchLookup(url, ["-L"])).toBeUndefined()
    expect(passiveResearchLookup(url, ["-H", "Authorization: Bearer $TOKEN"])).toBeUndefined()
    expect(passiveResearchLookup(url, ["-H", "X-API-Key: $OTX_API_KEY"])).toBeUndefined()
    expect(passiveResearchLookup(new URL("https://unlisted-provider.example/api"), ["-s"])).toBeUndefined()
    expect(passiveResearchLookup(new URL("https://unlisted-provider.example/search?domain=example.com"), ["-s"])).toEqual({
      targetURL: "https://example.com/",
      phase: "asset_discovery",
    })
    expect(passiveResearchLookup(new URL("https://unlisted-provider.example/search?domain=example.com&host=api.example.com"), ["-s"])).toBeUndefined()
    expect(passiveResearchLookup(new URL("https://crt.sh/?q=%.example.com&output=json"), ["-fsSL"])).toBeUndefined()
    expect(passiveResearchLookup(new URL("https://crt.sh/?q=%.example.com&output=json"), ["-d@payload.json"])).toBeUndefined()
  })
})

describe("Indirect scanner wrapper policy", () => {
  test("blocks actual xargs/parallel/find execution wrappers, not scanner names in search arguments", async () => {
    expect(await scannerLaunchedByWrapper(["xargs", "-I{}", "katana", "-u", "https://example.com"], 0)).toBe("katana")
    expect(await scannerLaunchedByWrapper(["parallel", "-j", "2", "katana", "-u", "https://example.com"], 0)).toBe("katana")
    expect(await scannerLaunchedByWrapper(["find", "/tmp", "-exec", "katana", "-u", "https://example.com", ";"], 0)).toBe("katana")
    expect(await scannerLaunchedByWrapper(["find", "/tmp", "-exec", "sh", "-c", "katana -u https://example.com", ";"], 0)).toBe("katana")
    expect(await scannerLaunchedByWrapper(["find", "/tmp", "-exec", "env", "FOO=bar", "katana", "-u", "https://example.com", ";"], 0)).toBe("katana")
    expect(await scannerLaunchedByWrapper(["xargs", "-I{}", "env", "FOO=bar", "katana", "-u", "https://example.com"], 0)).toBe("katana")
    expect(await scannerLaunchedByWrapper(["xargs", "grep", "katana", "notes.txt"], 0)).toBeUndefined()
    expect(await scannerLaunchedByWrapper(["find", "/tmp", "-iname", "*katana*"], 0)).toBeUndefined()
    expect(await scannerLaunchedByWrapper(["env", "FOO=bar", "katana", "-u", "https://example.com"], 0)).toBe("katana")
  })

  test("parses env split-string as a command but ignores quoted text in ordinary arguments", async () => {
    expect(await scannerLaunchedByWrapper(["env", "-S", "katana -u https://example.com"], 0)).toBe("katana")
    expect(await scannerLaunchedByWrapper(["env", "-S", "grep katana notes.txt"], 0)).toBeUndefined()
  })
})

describe("Recon scanner deduplication", () => {
  test("duplicate source scans share an identity even when output destinations differ", () => {
    const first = reconScannerInvocationKey([
      "katana", "-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", "/tmp/first.jsonl",
    ])
    const duplicate = reconScannerInvocationKey([
      "katana", "-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", "/tmp/second.jsonl",
    ])
    const complementary = reconScannerInvocationKey([
      "katana", "-u", "https://api.example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", "/tmp/api.jsonl",
    ])
    const wrappedFirst = reconScannerInvocationKey([
      "sudo", "-u", "tester", "katana", "-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", "/tmp/wrapped-first.jsonl",
    ])
    const wrappedDuplicate = reconScannerInvocationKey([
      "sudo", "-u", "tester", "katana", "-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", "/tmp/wrapped-second.jsonl",
    ])
    expect(first).toBe(duplicate)
    expect(first).not.toBe(complementary)
    expect(wrappedFirst).toBe(wrappedDuplicate)
  })

  test("installed active testing tools are recognized by the scope/phase gate", () => {
    for (const scanner of ["x8", "arjun", "commix", "ssrfmap", "nosqlmap", "crlfuzz", "git-dumper", "sqlmap", "dalfox", "wpscan"]) {
      expect(reconScannerInvocationKey([scanner, "-u", "https://example.com"])).toBeDefined()
    }
  })

  test("ordinary commands with scanner names as arguments are not identified as scans", () => {
    expect(reconScannerInvocationKey(["grep", "katana", "notes.txt"])).toBeUndefined()
  })
})

describe("Katana scope policy", () => {
  const baseScope: TargetScope = {
    schemaVersion: 1,
    targetURL: "https://example.com",
    status: "configured",
    scopeItems: ["example.com"],
    excludedItems: [],
    authorizationSource: "User-confirmed in conversation",
    authorizationReference: null,
    configuredAt: "2026-01-01T00:00:00.000Z",
  }
  const workspacePath = "/tmp/example-workspace"
  const safeOutput = path.join(workspacePath, "urls", "katana-urls-run-1.jsonl")
  const safeArgs = ["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-jc", "-j", "-ncb", "-silent", "-o", safeOutput]

  test("allows a bounded exact-host crawl when the saved scope is host-wide", () => {
    expect(katanaScopeBlockReason(safeArgs, "https://example.com", baseScope, workspacePath)).toBeUndefined()
  })

  test("accepts ordinary single- or double-quoted shell URL and numeric arguments", () => {
    const quotedArgs = ["-u", "'https://example.com'", "-fs", "fqdn", "-rl", "'5'", "-d", '"3"', "-j", "-ncb", "-o", "'/tmp/example-workspace/urls/katana-urls-run-1.jsonl'"]
    expect(katanaScopeBlockReason(quotedArgs, "https://example.com", baseScope, workspacePath)).toBeUndefined()
  })

  test("requires a unique direct output path inside the canonical workspace urls folder", () => {
    expect(katanaScopeBlockReason(["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb"], "https://example.com", baseScope, workspacePath)).toContain("raw results")
    expect(katanaScopeBlockReason(["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", "/tmp/outside.txt"], "https://example.com", baseScope, workspacePath)).toContain("inside")
    expect(katanaScopeBlockReason(["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", safeOutput], "https://example.com", baseScope, workspacePath)).toBeUndefined()
    const nestedOutput = path.join(workspacePath, "urls", "nested", "katana.jsonl")
    const nestedArgs = safeArgs.map((arg) => arg === safeOutput ? nestedOutput : arg)
    expect(katanaScopeBlockReason(nestedArgs, "https://example.com", baseScope, workspacePath)).toContain("direct child")
    const wrongExtension = path.join(workspacePath, "urls", "katana.txt")
    const wrongExtensionArgs = safeArgs.map((arg) => arg === safeOutput ? wrongExtension : arg)
    expect(katanaScopeBlockReason(wrongExtensionArgs, "https://example.com", baseScope, workspacePath)).toContain(".jsonl")
  })

  test("rejects a crawler command without explicit URL inputs", () => {
    expect(katanaScopeBlockReason(["-fs", "fqdn", "-rl", "5"], "https://example.com", baseScope)).toContain("explicit '-u")
  })

  test("rejects broad default scope and requires an explicit FQDN field scope", () => {
    expect(katanaScopeBlockReason(["-u", "https://example.com", "-rl", "5", "-o", safeOutput], "https://example.com", baseScope, workspacePath)).toContain("-fs fqdn")
  })

  test("requires explicit bounded crawl depth and a workspace-local output file", () => {
    const noDepth = ["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-o", "/tmp/katana.txt"]
    expect(katanaScopeBlockReason(noDepth, "https://example.com", baseScope, "/workspace/example")).toContain("explicit Katana depth")
    const noOutput = ["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb"]
    expect(katanaScopeBlockReason(noOutput, "https://example.com", baseScope, "/workspace/example")).toContain("raw results")
    const deeperCrawl = ["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "8", "-j", "-ncb", "-o", "/workspace/example/urls/katana.jsonl"]
    expect(katanaScopeBlockReason(deeperCrawl, "https://example.com", baseScope, "/workspace/example")).toBeUndefined()
    const invalidDepth = ["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "0", "-j", "-ncb", "-o", "/workspace/example/urls/katana-invalid.jsonl"]
    expect(katanaScopeBlockReason(invalidDepth, "https://example.com", baseScope, "/workspace/example")).toContain("positive safe integer")
    const outsideOutput = ["-u", "https://example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", "/tmp/katana.jsonl"]
    expect(katanaScopeBlockReason(outsideOutput, "https://example.com", baseScope, "/workspace/example")).toContain("output path must name a file inside")
  })

  test("rejects duplicate scope-sensitive flags so checked and effective settings cannot diverge", () => {
    expect(katanaScopeBlockReason([...safeArgs, "-o", path.join(workspacePath, "urls", "other.jsonl")], "https://example.com", baseScope, workspacePath)).toContain("Duplicate flags")
    expect(katanaScopeBlockReason(["-u", "https://example.com", "-u", "https://api.example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-o", safeOutput], "https://example.com", baseScope, workspacePath)).toContain("Duplicate flags")
  })

  test("requires explicit non-clobbering output and rejects scope-broadening flags", () => {
    const withoutNoClobber = safeArgs.filter((arg) => arg !== "-ncb")
    expect(katanaScopeBlockReason(withoutNoClobber, "https://example.com", baseScope, workspacePath)).toContain("no-clobber")
    expect(katanaScopeBlockReason(["-u", "https://example.com", "-fs", "fqdn", "-rl", "150", "-d", "3", "-j", "-ncb", "-o", safeOutput], "https://example.com", baseScope, workspacePath)).toContain("-rl 5")
    expect(katanaScopeBlockReason([...safeArgs, "-ns"], "https://example.com", baseScope, workspacePath)).toContain("scope overrides")
  })

  test("rejects URL-only and path-excluded scope because FQDN filtering cannot enforce those boundaries", () => {
    const urlOnlyScope = { ...baseScope, scopeItems: ["https://example.com/app"] }
    expect(katanaScopeBlockReason(safeArgs, "https://example.com/app", urlOnlyScope, workspacePath)).toContain("URL/path/port-only")
    const pathExcludedScope = { ...baseScope, excludedItems: ["https://example.com/admin"] }
    expect(katanaScopeBlockReason(safeArgs, "https://example.com", pathExcludedScope, workspacePath)).toContain("path/protocol/port exclusion")
  })

  test("preserves exclusions from ancestor workspace scopes", () => {
    const inheritedExclusion: TargetScope = {
      ...baseScope,
      excludedItems: ["https://example.com/private"],
    }
    expect(katanaScopeBlockReason(safeArgs, "https://example.com", [baseScope, inheritedExclusion], workspacePath)).toContain("path/protocol/port exclusion")
  })

  test("rejects exact-host URL and scheme-less path exclusions, including wildcard URL exclusions", () => {
    const exactURLExclusion = { ...baseScope, excludedItems: ["https://example.com/"] }
    expect(katanaScopeBlockReason(safeArgs, "https://example.com", exactURLExclusion, workspacePath)).toContain("URL/path/protocol/port exclusion")
    const schemeLessURLExclusion = { ...baseScope, excludedItems: ["url: example.com/private"] }
    expect(katanaScopeBlockReason(safeArgs, "https://example.com", schemeLessURLExclusion, workspacePath)).toContain("URL/path exclusion")
    const exactHostExclusionWithWildcardInclude = {
      ...baseScope,
      scopeItems: ["*.example.com"],
      excludedItems: ["url: example.com/private"],
    }
    const apiArgsForExactExclusion = safeArgs.map((arg) => arg === "https://example.com" ? "https://api.example.com" : arg)
    expect(katanaScopeBlockReason(apiArgsForExactExclusion, "https://api.example.com", exactHostExclusionWithWildcardInclude, workspacePath)).toBeUndefined()
    const wildcardURLExclusion = { ...baseScope, scopeItems: ["*.example.com"], excludedItems: ["https://*.example.com/"] }
    const apiArgs = safeArgs.map((arg) => arg === "https://example.com" ? "https://api.example.com" : arg)
    expect(katanaScopeBlockReason(apiArgs, "https://api.example.com", wildcardURLExclusion, workspacePath)).toContain("URL/path/protocol/port exclusion")
  })

  test("interprets typed wildcard scope entries as domain families", () => {
    const typedWildcard = { ...baseScope, scopeItems: ["wildcard: example.com"] }
    expect(katanaScopeBlockReason(["-u", "https://api.example.com", "-fs", "fqdn", "-rl", "5", "-d", "3", "-j", "-ncb", "-o", safeOutput], "https://api.example.com", typedWildcard, workspacePath)).toBeUndefined()
  })

  test("recognizes wildcard authorization but still rejects a scoped port exclusion", () => {
    const wildcardScope = { ...baseScope, scopeItems: ["*.example.com"], excludedItems: ["api.example.com:8443"] }
    const apiArgs = safeArgs.map((arg) => arg === "https://example.com" ? "https://api.example.com" : arg)
    expect(katanaScopeBlockReason(apiArgs, "https://api.example.com", wildcardScope, workspacePath)).toContain("port exclusion")
  })
})

describe("tool.bash permissions", () => {
  test("asks for bash permission with correct pattern", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute(
          {
            command: "echo hello",
            description: "Echo hello",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("bash")
        expect(requests[0].patterns).toContain("echo hello")
      },
    })
  })

  test("asks for bash permission with multiple commands", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute(
          {
            command: "echo foo && echo bar",
            description: "Echo twice",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("bash")
        expect(requests[0].patterns).toContain("echo foo")
        expect(requests[0].patterns).toContain("echo bar")
      },
    })
  })

  test("asks for external_directory permission when cd to parent", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute(
          {
            command: "cd ../",
            description: "Change to parent directory",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
      },
    })
  })

  test("asks for external_directory permission when workdir is outside project", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute(
          {
            command: "ls",
            workdir: "/tmp",
            description: "List /tmp",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
        expect(extDirReq!.patterns).toContain("/tmp/*")
      },
    })
  })

  test("asks for external_directory permission when file arg is outside project", async () => {
    await using outerTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "outside.txt"), "x")
      },
    })
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        const filepath = path.join(outerTmp.path, "outside.txt")
        await bash.execute(
          {
            command: `cat ${filepath}`,
            description: "Read external file",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        const expected = path.join(outerTmp.path, "*")
        expect(extDirReq).toBeDefined()
        expect(extDirReq!.patterns).toContain(expected)
        expect(extDirReq!.always).toContain(expected)
      },
    })
  })

  test("does not ask for external_directory permission when rm inside project", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }

        await Bun.write(path.join(tmp.path, "tmpfile"), "x")

        await bash.execute(
          {
            command: "rm tmpfile",
            description: "Remove tmpfile",
          },
          testCtx,
        )

        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeUndefined()
      },
    })
  })

  test("includes always patterns for auto-approval", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute(
          {
            command: "git log --oneline -5",
            description: "Git log",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].always.length).toBeGreaterThan(0)
        expect(requests[0].always.some((p) => p.endsWith("*"))).toBe(true)
      },
    })
  })

  test("does not ask for bash permission when command is cd only", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute(
          {
            command: "cd .",
            description: "Stay in current directory",
          },
          testCtx,
        )
        const bashReq = requests.find((r) => r.permission === "bash")
        expect(bashReq).toBeUndefined()
      },
    })
  })

  test("matches redirects in permission pattern", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute({ command: "cat > /tmp/output.txt", description: "Redirect ls output" }, testCtx)
        const bashReq = requests.find((r) => r.permission === "bash")
        expect(bashReq).toBeDefined()
        expect(bashReq!.patterns).toContain("cat > /tmp/output.txt")
      },
    })
  })

  test("always pattern has space before wildcard to not include different commands", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await bash.execute({ command: "ls -la", description: "List" }, testCtx)
        const bashReq = requests.find((r) => r.permission === "bash")
        expect(bashReq).toBeDefined()
        const pattern = bashReq!.always[0]
        expect(pattern).toBe("ls *")
      },
    })
  })
})

describe("tool.bash truncation", () => {
  test("truncates output exceeding line limit", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const bash = await BashTool.init()
        const lineCount = Truncate.MAX_LINES + 500
        const result = await bash.execute(
          {
            command: `seq 1 ${lineCount}`,
            description: "Generate lines exceeding limit",
          },
          ctx,
        )
        expect((result.metadata as any).truncated).toBe(true)
        expect(result.output).toContain("truncated")
        expect(result.output).toContain("The tool call succeeded but the output was truncated")
      },
    })
  })

  test("truncates output exceeding byte limit", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const bash = await BashTool.init()
        const byteCount = Truncate.MAX_BYTES + 10000
        const result = await bash.execute(
          {
            command: `head -c ${byteCount} /dev/zero | tr '\\0' 'a'`,
            description: "Generate bytes exceeding limit",
          },
          ctx,
        )
        expect((result.metadata as any).truncated).toBe(true)
        expect(result.output).toContain("truncated")
        expect(result.output).toContain("The tool call succeeded but the output was truncated")
      },
    })
  })

  test("does not truncate small output", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const bash = await BashTool.init()
        const result = await bash.execute(
          {
            command: "echo hello",
            description: "Echo hello",
          },
          ctx,
        )
        expect((result.metadata as any).truncated).toBe(false)
        expect(result.output).toBe("hello\n")
      },
    })
  })

  test("full output is saved to file when truncated", async () => {
    await Instance.provide({
      directory: projectRoot,
      fn: async () => {
        const bash = await BashTool.init()
        const lineCount = Truncate.MAX_LINES + 100
        const result = await bash.execute(
          {
            command: `seq 1 ${lineCount}`,
            description: "Generate lines for file check",
          },
          ctx,
        )
        expect((result.metadata as any).truncated).toBe(true)

        const filepath = (result.metadata as any).outputPath
        expect(filepath).toBeTruthy()

        const saved = await Bun.file(filepath).text()
        const lines = saved.trim().split("\n")
        expect(lines.length).toBe(lineCount)
        expect(lines[0]).toBe("1")
        expect(lines[lineCount - 1]).toBe(String(lineCount))
      },
    })
  })
})
