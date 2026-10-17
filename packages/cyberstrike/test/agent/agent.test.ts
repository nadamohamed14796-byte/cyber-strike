import { test, expect } from "bun:test"
import path from "path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Agent } from "../../src/agent/agent"
import { Skill } from "../../src/skill"
import { SkillIndex } from "../../src/skill/index-engine"
import { PermissionNext } from "../../src/permission/next"

// Helper to evaluate permission for a tool with wildcard pattern
function evalPerm(agent: Agent.Info | undefined, permission: string): PermissionNext.Action | undefined {
  if (!agent) return undefined
  return PermissionNext.evaluate(permission, "*", agent.permission).action
}

test("embedded vulnerability-agent skills resolve directory aliases", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".cyberstrike", "skill", "wstg-authz-04")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `---
name: readable-authorization-guide
description: Skill available through a directory alias.
---

# Authorization methodology

EMBEDDED_SKILL_ALIAS_REGRESSION_MARKER
`,
      )
    },
  })

  const previousHome = process.env.CYBERSTRIKE_TEST_HOME
  process.env.CYBERSTRIKE_TEST_HOME = tmp.path
  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const tester = await Agent.get("proxy-tester-idor")
        expect(tester?.prompt).toContain("EMBEDDED_SKILL_ALIAS_REGRESSION_MARKER")
        expect(tester?.prompt).toContain('<skill name="wstg-authz-04">')
      },
    })
  } finally {
    if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
    else process.env.CYBERSTRIKE_TEST_HOME = previousHome
  }
})

test("agent initialization fails loudly when a required embedded skill is missing", async () => {
  await using tmp = await tmpdir({ git: true })
  const previousHome = process.env.CYBERSTRIKE_TEST_HOME
  process.env.CYBERSTRIKE_TEST_HOME = tmp.path
  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        await expect(Agent.get("proxy-tester-idor")).rejects.toThrow(
          /references unavailable skill "wstg-authz-04"/,
        )
      },
    })
  } finally {
    if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
    else process.env.CYBERSTRIKE_TEST_HOME = previousHome
  }
})

test("every built-in agent skill reference resolves to a loadable skill", async () => {
  const repoRoot = path.resolve(import.meta.dir, "../../../..")
  const previousHome = process.env.CYBERSTRIKE_TEST_HOME
  delete process.env.CYBERSTRIKE_TEST_HOME
  try {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        await SkillIndex.rebuild()
        for (const agent of await Agent.list()) {
          for (const reference of agent.skills ?? []) {
            const direct = await Skill.get(reference)
            const canonical = SkillIndex.resolveReference(reference)
            const resolved = direct ?? (canonical ? await Skill.get(canonical) : undefined)
            expect(resolved, `agent "${agent.name}" references unresolved skill "${reference}"`).toBeDefined()
          }
        }

        // These are injected directly by loadVulnAgent(), not stored in agent.skills.
        // Check the rendered prompt so a stale/missing alias cannot silently remove
        // baseline methodology while the dynamic SkillTool still works.
        const embeddedReferences: Record<string, string[]> = {
          "proxy-tester-idor": ["wstg-authz-04", "wstg-apit-02"],
          "proxy-tester-authz": ["wstg-authz-02", "wstg-authz-03", "wstg-authz-01"],
          "proxy-tester-mass-assignment": ["wstg-inpv-20", "wstg-busl-02"],
          "proxy-tester-injection": ["wstg-injection", "wstg-inpv-05", "wstg-inpv-12", "wstg-inpv-18"],
          "proxy-tester-authn": ["wstg-auth-session", "wstg-athn-04", "wstg-athn-09", "wstg-athn-11", "wstg-sess-10"],
          "proxy-tester-business-logic": ["wstg-logic-client-api", "wstg-busl-04", "wstg-busl-10"],
          "proxy-tester-ssrf": ["wstg-inpv-19", "wstg-conf-13"],
          "proxy-tester-file-attacks": ["wstg-inpv-11.1", "wstg-inpv-11", "wstg-busl-08", "wstg-busl-09"],
          "proxy-tester-llm": ["llm-security"],
        }
        for (const [agentName, references] of Object.entries(embeddedReferences)) {
          const agent = await Agent.get(agentName)
          expect(agent, `missing vulnerability agent "${agentName}"`).toBeDefined()
          for (const reference of references) {
            expect(agent?.prompt, `"${agentName}" prompt is missing embedded skill "${reference}"`).toContain(
              `<skill name="${reference}">`,
            )
          }
        }
      },
    })
  } finally {
    if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
    else process.env.CYBERSTRIKE_TEST_HOME = previousHome
  }
}, 60000)

test("returns default native agents when no config", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agents = await Agent.list()
      const names = agents.map((a) => a.name)
      expect(names).toContain("cyberstrike")
      expect(names).toContain("general")
      expect(names).toContain("explore")
      expect(names).toContain("compaction")
      expect(names).toContain("title")
      expect(names).toContain("summary")
    },
  })
})

test("cyberstrike agent has correct default properties", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs).toBeDefined()
      expect(cs?.mode).toBe("primary")
      expect(cs?.native).toBe(true)
      expect(evalPerm(cs, "edit")).toBe("allow")
      expect(evalPerm(cs, "bash")).toBe("allow")
    },
  })
})

test("proxy vulnerability agents can retrieve shared global research and validation tools", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const testerNames = [
        "proxy-tester-idor",
        "proxy-tester-authz",
        "proxy-tester-mass-assignment",
        "proxy-tester-injection",
        "proxy-tester-authn",
        "proxy-tester-business-logic",
        "proxy-tester-ssrf",
        "proxy-tester-file-attacks",
        "proxy-tester-llm",
      ] as const
      const testers = await Promise.all(testerNames.map((name) => Agent.get(name)))
      const orchestrator = await Agent.get("proxy-agent")
      const analyzer = await Agent.get("proxy-analyzer")
      expect(orchestrator).toBeDefined()
      expect(analyzer).toBeDefined()
      expect(orchestrator?.mode).toBe("subagent")

      for (let i = 0; i < testerNames.length; i++) {
        const tester = testers[i]
        expect(tester, testerNames[i]).toBeDefined()
        expect(evalPerm(tester, "research_knowledge"), testerNames[i]).toBe("allow")
        expect(evalPerm(tester, "false_positive_memory"), testerNames[i]).toBe("allow")
        expect(evalPerm(tester, "validate_finding"), testerNames[i]).toBe("allow")
        expect(evalPerm(tester, "correlate_javascript"), testerNames[i]).toBe("allow")
        expect(evalPerm(tester, "report_vulnerability"), testerNames[i]).toBe("allow")
        expect(evalPerm(tester, "http_replay"), testerNames[i]).toBe("allow")
        expect(tester?.prompt, testerNames[i]).toContain("Global Research")
      }

      expect(evalPerm(orchestrator, "research_knowledge")).toBe("allow")
      expect(evalPerm(orchestrator, "web_get_request_detail")).toBe("allow")
      expect(evalPerm(orchestrator, "correlate_javascript")).toBe("allow")
      expect(evalPerm(orchestrator, "triage_vulnerability")).toBe("allow")
      expect(evalPerm(orchestrator, "report_vulnerability")).toBe("deny")
      // The orchestrator must not contradict its pure-orchestration contract by
      // instructing itself to synthesize/send unobserved form submissions.
      expect(orchestrator?.prompt).toContain("pure orchestrator")
      expect(orchestrator?.prompt).toContain("never invent an endpoint, body")
      expect(orchestrator?.prompt).toContain("call `scope_check`")
      expect(orchestrator?.prompt).toContain("captured request is evidence that the browser observed traffic, NOT proof")
      expect(orchestrator?.prompt).toContain("Every specialist must still rely on its own execution-boundary scope enforcement")
      expect(orchestrator?.prompt).toContain("Reflection alone proves none of these")
      expect(orchestrator?.prompt).not.toContain("synthesize and send it yourself")
      expect(orchestrator?.prompt).not.toContain("POST the form's action")
      expect(orchestrator?.prompt).not.toContain("SQLi + XSS + SSTI on EVERY field")
      expect(orchestrator?.prompt).not.toContain("always, unconditionally")
      expect(orchestrator?.prompt).not.toContain("name the full floor (SQLi + XSS + SSTI) every time")
      expect(orchestrator?.prompt).toContain("A free-text field alone is NOT proof")
      expect(orchestrator?.prompt).toContain("Evidence-Grounded Dispatch Examples")
      expect(orchestrator?.prompt).toContain("never dispatch every specialist to satisfy a fixed checklist")
      expect(orchestrator?.prompt).toContain("tester-owned")
      expect(orchestrator?.prompt).not.toContain("The field is ALSO a SQLi sink")
      expect(orchestrator?.prompt).not.toContain("test SQLi in email/name")
      expect(orchestrator?.prompt).not.toContain("try injecting role, is_admin fields")
      expect(orchestrator?.prompt).not.toContain("try sequential IDs")
      expect(orchestrator?.prompt).not.toContain("double-spend")
      expect(orchestrator?.prompt).not.toContain("POST to /step5 directly")
      expect(orchestrator?.prompt).not.toContain("Tests all injection types")
      expect(orchestrator?.prompt).not.toContain("Effective when: request accepts user input")
      expect(orchestrator?.prompt).not.toContain("try sequential, negative, admin IDs")
      expect(orchestrator?.prompt).not.toContain("tests internal IP ranges, localhost, cloud metadata")
      expect(orchestrator?.prompt).not.toContain("path traversal (../../etc/passwd)")
      expect(orchestrator?.prompt).toContain("A URL-like parameter alone is insufficient")
      expect(orchestrator?.prompt).toContain("Do not trigger real payments, transfers, destructive actions")
      expect(orchestrator?.prompt).toContain("a bearer header alone does not justify token tampering")
      expect(orchestrator?.prompt).toContain("Do not route this to SSRF without separate server-side-fetch evidence")
      expect(orchestrator?.prompt).not.toContain("ssrf, authz (path normalization bypass)")
      expect(orchestrator?.prompt).toContain("numeric/UUID shape alone is not enough")
      expect(orchestrator?.prompt).not.toContain("JWT analysis triggered on any Bearer token")
      expect(orchestrator?.prompt).not.toContain("path-confusion-prone routes → proxy-tester-ssrf")
      expect(evalPerm(analyzer, "research_knowledge")).toBe("allow")
      expect(evalPerm(analyzer, "correlate_javascript")).toBe("allow")
      expect(evalPerm(analyzer, "report_vulnerability")).toBe("deny")

      for (const name of ["web-application", "mobile-application", "cloud-security", "internal-network", "general"]) {
        expect(evalPerm(await Agent.get(name), "research_knowledge"), name).toBe("allow")
      }
    },
  })
})

test("specialized proxy tools stay limited to their intended tester agents", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const injection = await Agent.get("proxy-tester-injection")
      const fileAttacks = await Agent.get("proxy-tester-file-attacks")
      const llm = await Agent.get("proxy-tester-llm")
      const idor = await Agent.get("proxy-tester-idor")

      expect(evalPerm(injection, "inject_probe")).toBe("allow")
      expect(injection?.prompt).toContain("Evidence-Grounded First Move")
      expect(injection?.prompt).toContain("scope_check")
      expect(injection?.prompt).toContain("A request containing a parameter is not by itself an injection hypothesis")
      expect(injection?.prompt).toContain("20 distinct valid evidence-backed attempts")
      expect(injection?.prompt).toContain("Step 6: Record attempts and validate the finding")
      expect(injection?.prompt).toContain("A WAF, filter, or validation response is an observation")
      expect(injection?.prompt).not.toContain("On ANY request carrying a parameter")
      expect(injection?.prompt).not.toContain("YOU confirm, weaponize, and extract")
      expect(injection?.prompt).not.toContain("A single `SELECT version()` returning a real value is enough proof")
      expect(injection?.prompt).not.toContain("escalate (encoding/evasion, different vantage)")
      expect(injection?.prompt).not.toContain("test your class")
      expect(injection?.prompt).not.toContain("a couple of probes settle it")
      expect(evalPerm(fileAttacks, "inject_probe")).toBe("allow")
      expect(evalPerm(idor, "inject_probe")).toBe("deny")
      expect(evalPerm(llm, "llmhook")).toBe("allow")
      expect(evalPerm(idor, "llmhook")).toBe("deny")

      for (const agent of [injection, fileAttacks, llm, idor]) {
        expect(evalPerm(agent, "webfetch")).toBe("deny")
        expect(evalPerm(agent, "http_replay")).toBe("allow")
      }
    },
  })
})

test("web application prompt requires evidence-led, non-destructive testing", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const webApp = await Agent.get("web-application")
      expect(webApp).toBeDefined()
      expect(webApp?.prompt).toContain("A parameter or free-text field alone is not sufficient")
      expect(webApp?.prompt).toContain("Use tester-owned, reversible fixtures")
      expect(webApp?.prompt).not.toContain("SQLi: all input vectors")
      expect(webApp?.prompt).not.toContain("SSRF: internal URLs, cloud metadata")
      expect(webApp?.prompt).not.toContain("Test login bypass, default creds, brute force lockout")
      expect(webApp?.prompt).not.toContain("web shells, polyglot files")
    },
  })
})

test("explore agent denies edits", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore).toBeDefined()
      expect(evalPerm(explore, "edit")).toBe("deny")
    },
  })
})

test("explore agent denies edit and write", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore).toBeDefined()
      expect(explore?.mode).toBe("subagent")
      expect(evalPerm(explore, "edit")).toBe("deny")
      expect(evalPerm(explore, "write")).toBe("deny")
      expect(evalPerm(explore, "todoread")).toBe("deny")
      expect(evalPerm(explore, "todowrite")).toBe("deny")
    },
  })
})

test("general agent denies todo tools", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const general = await Agent.get("general")
      expect(general).toBeDefined()
      expect(general?.mode).toBe("subagent")
      expect(general?.hidden).toBeUndefined()
      expect(evalPerm(general, "todoread")).toBe("deny")
      expect(evalPerm(general, "todowrite")).toBe("deny")
    },
  })
})

test("compaction agent denies all permissions", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const compaction = await Agent.get("compaction")
      expect(compaction).toBeDefined()
      expect(compaction?.hidden).toBe(true)
      expect(evalPerm(compaction, "bash")).toBe("deny")
      expect(evalPerm(compaction, "edit")).toBe("deny")
      expect(evalPerm(compaction, "read")).toBe("deny")
    },
  })
})

test("custom agent from config creates new agent", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        my_custom_agent: {
          model: "openai/gpt-4",
          description: "My custom agent",
          temperature: 0.5,
          top_p: 0.9,
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const custom = await Agent.get("my_custom_agent")
      expect(custom).toBeDefined()
      expect(custom?.model?.providerID).toBe("openai")
      expect(custom?.model?.modelID).toBe("gpt-4")
      expect(custom?.description).toBe("My custom agent")
      expect(custom?.temperature).toBe(0.5)
      expect(custom?.topP).toBe(0.9)
      expect(custom?.native).toBe(false)
      expect(custom?.mode).toBe("all")
    },
  })
})

test("custom agent config overrides native agent properties", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: {
          model: "anthropic/claude-3",
          description: "Custom cyberstrike agent",
          temperature: 0.7,
          color: "#FF0000",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs).toBeDefined()
      expect(cs?.model?.providerID).toBe("anthropic")
      expect(cs?.model?.modelID).toBe("claude-3")
      expect(cs?.description).toBe("Custom cyberstrike agent")
      expect(cs?.temperature).toBe(0.7)
      expect(cs?.color).toBe("#FF0000")
      expect(cs?.native).toBe(true)
    },
  })
})

test("agent disable removes agent from list", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        explore: { disable: true },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore).toBeUndefined()
      const agents = await Agent.list()
      const names = agents.map((a) => a.name)
      expect(names).not.toContain("explore")
    },
  })
})

test("agent permission config merges with defaults", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: {
          permission: {
            bash: {
              "rm -rf *": "deny",
            },
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs).toBeDefined()
      // Specific pattern is denied
      expect(PermissionNext.evaluate("bash", "rm -rf *", cs!.permission).action).toBe("deny")
      // Edit still allowed
      expect(evalPerm(cs, "edit")).toBe("allow")
    },
  })
})

test("global permission config applies to all agents", async () => {
  await using tmp = await tmpdir({
    config: {
      permission: {
        bash: "deny",
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs).toBeDefined()
      expect(evalPerm(cs, "bash")).toBe("deny")
    },
  })
})

test("agent steps/maxSteps config sets steps property", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: { steps: 50 },
        general: { maxSteps: 100 },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      const general = await Agent.get("general")
      expect(cs?.steps).toBe(50)
      expect(general?.steps).toBe(100)
    },
  })
})

test("agent mode can be overridden", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        explore: { mode: "primary" },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const explore = await Agent.get("explore")
      expect(explore?.mode).toBe("primary")
    },
  })
})

test("agent name can be overridden", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: { name: "Striker" },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs?.name).toBe("Striker")
    },
  })
})

test("agent prompt can be set from config", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: { prompt: "Custom system prompt" },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs?.prompt).toBe("Custom system prompt")
    },
  })
})

test("unknown agent properties are placed into options", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: {
          random_property: "hello",
          another_random: 123,
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs?.options.random_property).toBe("hello")
      expect(cs?.options.another_random).toBe(123)
    },
  })
})

test("agent options merge correctly", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: {
          options: {
            custom_option: true,
            another_option: "value",
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(cs?.options.custom_option).toBe(true)
      expect(cs?.options.another_option).toBe("value")
    },
  })
})

test("multiple custom agents can be defined", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        agent_a: {
          description: "Agent A",
          mode: "subagent",
        },
        agent_b: {
          description: "Agent B",
          mode: "primary",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agentA = await Agent.get("agent_a")
      const agentB = await Agent.get("agent_b")
      expect(agentA?.description).toBe("Agent A")
      expect(agentA?.mode).toBe("subagent")
      expect(agentB?.description).toBe("Agent B")
      expect(agentB?.mode).toBe("primary")
    },
  })
})

test("Agent.get returns undefined for non-existent agent", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const nonExistent = await Agent.get("does_not_exist")
      expect(nonExistent).toBeUndefined()
    },
  })
})

test("default permission includes doom_loop and external_directory as ask", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(evalPerm(cs, "doom_loop")).toBe("ask")
      expect(evalPerm(cs, "external_directory")).toBe("ask")
    },
  })
})

test("webfetch is allowed by default", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(evalPerm(cs, "webfetch")).toBe("allow")
    },
  })
})

test("legacy tools config converts to permissions", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: {
          tools: {
            bash: false,
            read: false,
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(evalPerm(cs, "bash")).toBe("deny")
      expect(evalPerm(cs, "read")).toBe("deny")
    },
  })
})

test("legacy tools config maps write/edit/patch/multiedit to edit permission", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: {
          tools: {
            write: false,
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(evalPerm(cs, "edit")).toBe("deny")
    },
  })
})

test("Truncate.GLOB is allowed even when user denies external_directory globally", async () => {
  const { Truncate } = await import("../../src/tool/truncation")
  await using tmp = await tmpdir({
    config: {
      permission: {
        external_directory: "deny",
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(PermissionNext.evaluate("external_directory", Truncate.GLOB, cs!.permission).action).toBe("allow")
      expect(PermissionNext.evaluate("external_directory", Truncate.DIR, cs!.permission).action).toBe("deny")
      expect(PermissionNext.evaluate("external_directory", "/some/other/path", cs!.permission).action).toBe("deny")
    },
  })
})

test("Truncate.GLOB is allowed even when user denies external_directory per-agent", async () => {
  const { Truncate } = await import("../../src/tool/truncation")
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: {
          permission: {
            external_directory: "deny",
          },
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(PermissionNext.evaluate("external_directory", Truncate.GLOB, cs!.permission).action).toBe("allow")
      expect(PermissionNext.evaluate("external_directory", Truncate.DIR, cs!.permission).action).toBe("deny")
      expect(PermissionNext.evaluate("external_directory", "/some/other/path", cs!.permission).action).toBe("deny")
    },
  })
})

test("explicit Truncate.GLOB deny is respected", async () => {
  const { Truncate } = await import("../../src/tool/truncation")
  await using tmp = await tmpdir({
    config: {
      permission: {
        external_directory: {
          "*": "deny",
          [Truncate.GLOB]: "deny",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const cs = await Agent.get("cyberstrike")
      expect(PermissionNext.evaluate("external_directory", Truncate.GLOB, cs!.permission).action).toBe("deny")
      expect(PermissionNext.evaluate("external_directory", Truncate.DIR, cs!.permission).action).toBe("deny")
    },
  })
})

test("skill directories are allowed for external_directory", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".cyberstrike", "skill", "perm-skill")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `---
name: perm-skill
description: Permission skill.
---

# Permission Skill
`,
      )
    },
  })

  const home = process.env.CYBERSTRIKE_TEST_HOME
  process.env.CYBERSTRIKE_TEST_HOME = tmp.path

  try {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const cs = await Agent.get("cyberstrike")
        const skillDir = path.join(tmp.path, ".cyberstrike", "skill", "perm-skill")
        const target = path.join(skillDir, "reference", "notes.md")
        expect(PermissionNext.evaluate("external_directory", target, cs!.permission).action).toBe("allow")
      },
    })
  } finally {
    process.env.CYBERSTRIKE_TEST_HOME = home
  }
})

test("defaultAgent returns cyberstrike when no default_agent config", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      expect(agent).toBe("cyberstrike")
    },
  })
})

test("defaultAgent respects default_agent config set to general", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "my_primary",
      agent: {
        my_primary: {
          description: "Custom primary agent",
          mode: "primary",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      expect(agent).toBe("my_primary")
    },
  })
})

test("defaultAgent respects default_agent config set to custom agent with mode all", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "my_custom",
      agent: {
        my_custom: {
          description: "My custom agent",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      expect(agent).toBe("my_custom")
    },
  })
})

test("defaultAgent throws when default_agent points to subagent", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "explore",
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      await expect(Agent.defaultAgent()).rejects.toThrow('default agent "explore" is a subagent')
    },
  })
})

test("defaultAgent throws when default_agent points to hidden agent", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "compaction",
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      await expect(Agent.defaultAgent()).rejects.toThrow('default agent "compaction" is a subagent')
    },
  })
})

test("defaultAgent throws when default_agent points to non-existent agent", async () => {
  await using tmp = await tmpdir({
    config: {
      default_agent: "does_not_exist",
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      await expect(Agent.defaultAgent()).rejects.toThrow('default agent "does_not_exist" not found')
    },
  })
})

test("defaultAgent returns next primary when cyberstrike is disabled", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: { disable: true },
        fallback: {
          description: "Fallback agent",
          mode: "primary",
        },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const agent = await Agent.defaultAgent()
      // cyberstrike is disabled, so it should return the next primary agent
      expect(agent).toBe("fallback")
    },
  })
})

test("defaultAgent throws when all primary agents are disabled", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        cyberstrike: { disable: true },
      },
    },
  })
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      // cyberstrike is the only primary agent, disabled = no primary visible agents remain
      await expect(Agent.defaultAgent()).rejects.toThrow("no primary visible agent found")
    },
  })
})
