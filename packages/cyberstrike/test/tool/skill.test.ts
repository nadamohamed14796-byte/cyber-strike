import { describe, expect, spyOn, test } from "bun:test"
import path from "path"
import fs from "node:fs/promises"
import { fileURLToPath, pathToFileURL } from "url"
import type { PermissionNext } from "../../src/permission/next"
import type { Tool } from "../../src/tool/tool"
import { Instance } from "../../src/project/instance"
import { SkillTool } from "../../src/tool/skill"
import { ReadTool } from "../../src/tool/read"
import { SkillContext } from "../../src/skill/context"
import { SkillIndex } from "../../src/skill/index-engine"
import { tmpdir } from "../fixture/fixture"

const baseCtx: Omit<Tool.Context, "ask"> = {
  sessionID: "test",
  messageID: "",
  callID: "",
  agent: "cyberstrike",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => {},
}

describe("tool.skill", () => {
  test("missing skill load fails explicitly instead of reporting a successful load", async () => {
    await using tmp = await tmpdir({ git: true })
    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const tool = await SkillTool.init()
          await expect(
            tool.execute(
              { action: "load", name: "skill-that-does-not-exist" },
              { ...baseCtx, ask: async () => {} },
            ),
          ).rejects.toThrow(/not found or has an ambiguous metadata reference/)
          expect(SkillContext.isLoaded("skill-that-does-not-exist")).toBe(false)
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("skill access fails closed when the caller agent identity cannot be resolved", async () => {
    await using tmp = await tmpdir({ git: true })
    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const tool = await SkillTool.init()
          await expect(
            tool.execute(
              { action: "list" },
              { ...baseCtx, agent: "not-a-registered-agent", ask: async () => {} },
            ),
          ).rejects.toThrow(/refusing to bypass skill permissions/)
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("loaded skill context is isolated between agent sessions", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        const skillDir = path.join(dir, ".cyberstrike", "skill", "workspace-skill-alias")
        await Bun.write(
          path.join(skillDir, "SKILL.md"),
          ["---", "name: workspace-skill", "description: Session isolation fixture.", "---", "", "# Shared skill", "SHARED_SKILL_CONTEXT_MARKER", ""].join("\n"),
        )
      },
    })

    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const tool = await SkillTool.init()
          const parentCtx: Tool.Context = {
            ...baseCtx,
            sessionID: "parent-session",
            agent: "build",
            ask: async () => {},
          }
          const childCtx: Tool.Context = {
            ...baseCtx,
            sessionID: "child-session",
            agent: "general",
            ask: async () => {},
          }
          const parentScope = { sessionID: parentCtx.sessionID, agent: parentCtx.agent }
          const childScope = { sessionID: childCtx.sessionID, agent: childCtx.agent }

          const parentLoad = await tool.execute({ action: "load", name: "workspace-skill-alias" }, parentCtx)
          expect(parentLoad.title).toBe("Loaded skill: workspace-skill")
          expect(SkillContext.active(parentScope)).toEqual(["workspace-skill"])
          expect(SkillContext.active(childScope)).toEqual([])
          expect((await tool.execute({ action: "list", loaded: true }, childCtx)).title).toBe("No skills loaded")

          const parentTokens = SkillContext.tokenCount(parentScope)
          const childLoad = await tool.execute({ action: "load", name: "workspace-skill" }, childCtx)
          expect(childLoad.title).toBe("Loaded skill: workspace-skill")
          expect(SkillContext.active(parentScope)).toEqual(["workspace-skill"])
          expect(SkillContext.active(childScope)).toEqual(["workspace-skill"])
          expect(SkillContext.tokenCount(parentScope)).toBe(parentTokens)
          expect(SkillContext.tokenCount(childScope)).toBeGreaterThan(0)

          const unloaded = await tool.execute({ action: "unload", name: "workspace-skill-alias" }, parentCtx)
          expect(unloaded.title).toBe("Unloaded: workspace-skill")
          expect(SkillContext.active(parentScope)).toEqual([])
          expect(SkillContext.active(childScope)).toEqual(["workspace-skill"])
          expect((await tool.execute({ action: "list", loaded: true }, childCtx)).output).toContain("workspace-skill")
          SkillContext.clear()
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })
  test("list and search paginate large skill catalogs", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        for (const name of ["tool-skill-a", "tool-skill-b", "tool-skill-c"]) {
          const skillDir = path.join(dir, ".cyberstrike", "skill", name)
          await Bun.write(
            path.join(skillDir, "SKILL.md"),
            ["---", "name: " + name, "description: Pagination fixture skill.", "tags: [" + (name === "tool-skill-b" ? "routing-test" : "other-test") + "]", "tech_stack: [" + (name === "tool-skill-b" ? "node" : "python") + "]", "---", "", "# " + name, ""].join("\n"),
          )
        }
      },
    })

    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const tool = await SkillTool.init()
          const ctx: Tool.Context = { ...baseCtx, ask: async () => {} }

          const firstListPage = await tool.execute({ action: "list", limit: 2, offset: 0 }, ctx)
          expect(firstListPage.output).toContain("showing 1-2 of 3")
          expect(firstListPage.output).toContain("More skills remain")
          expect(firstListPage.output).not.toContain("tool-skill-c")

          const secondListPage = await tool.execute({ action: "list", limit: 2, offset: 2 }, ctx)
          expect(secondListPage.output).toContain("tool-skill-c")
          expect(secondListPage.output).not.toContain("tool-skill-a")

          const secondSearchPage = await tool.execute({ action: "search", query: "tool-skill", limit: 2, offset: 2 }, ctx)
          expect(secondSearchPage.output).toContain("tool-skill-c")
          expect(secondSearchPage.output).toContain("showing 3-3 of 3")

          const taggedSearch = await tool.execute({ action: "search", tag: "routing-test" }, ctx)
          expect(taggedSearch.output).toContain("tool-skill-b")
          expect(taggedSearch.output).not.toContain("tool-skill-a")
          expect(taggedSearch.output).not.toContain("tool-skill-c")

          const combinedSearch = await tool.execute(
            { action: "search", query: "tool-skill", tag: "routing-test", tech: ["node"] },
            ctx,
          )
          expect(combinedSearch.output).toContain("tool-skill-b")
          expect(combinedSearch.output).not.toContain("tool-skill-a")
          expect(combinedSearch.output).not.toContain("tool-skill-c")
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("missing skill errors guide discovery without dumping the full catalog", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        for (let index = 0; index < 20; index++) {
          const name = "catalog-skill-" + String(index).padStart(2, "0")
          const skillDir = path.join(dir, ".cyberstrike", "skill", name)
          await Bun.write(
            path.join(skillDir, "SKILL.md"),
            ["---", "name: " + name, "description: Catalog fixture skill.", "---", "", "# " + name, ""].join("\n"),
          )
        }
      },
    })
    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const tool = await SkillTool.init()
          const ctx: Tool.Context = { ...baseCtx, ask: async () => {} }
          await expect(tool.execute({ action: "load", name: "does-not-exist" }, ctx)).rejects.toThrow(
            'Use skill(action="search", query="...") or paged skill(action="list")',
          )
          try {
            await tool.execute({ action: "load", name: "does-not-exist" }, ctx)
            throw new Error("Expected missing skill to fail")
          } catch (error) {
            expect(String(error)).not.toContain("catalog-skill-19")
          }
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("description explains available skills and search", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        const skillDir = path.join(dir, ".cyberstrike", "skill", "tool-skill")
        await Bun.write(
          path.join(skillDir, "SKILL.md"),
          `---
name: tool-skill
description: Skill for tool tests.
owasp_id: T1078.004
---

# Tool Skill
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
          const tool = await SkillTool.init()
          expect(tool.description).toContain("skills available")
          expect(tool.description).toContain("search")
        },
      })
    } finally {
      process.env.CYBERSTRIKE_TEST_HOME = home
    }
  })

  test("outline previews a skill without loading its full content", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        const skillDir = path.join(dir, ".cyberstrike", "skill", "large-skill")
        await Bun.write(
          path.join(skillDir, "SKILL.md"),
          [
            "---",
            "name: large-skill",
            "description: A skill used to test compact previews.",
            "---",
            "",
            "# Main Guide",
            "",
            "A short introduction.",
            "",
            "## Phase One",
            "",
            "DETAILS_SHOULD_NOT_BE_IN_OUTLINE",
            ...Array.from({ length: 300 }, (_, index) => "Long procedure line " + index),
            "",
            "## Verification",
            "",
            "Check the evidence.",
          ].join("\n"),
        )
      },
    })
    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const tool = await SkillTool.init()
          const result = await tool.execute(
            { action: "outline", name: "large-skill" },
            { ...baseCtx, ask: async () => { throw new Error("outline must not request load permission") } },
          )
          expect(result.output).toContain("## Main Guide")
          expect(result.output).toContain("## Phase One")
          expect(result.output).toContain("## Verification")
          expect(result.output).toContain("full skill content has NOT been loaded")
          expect(result.output).not.toContain("DETAILS_SHOULD_NOT_BE_IN_OUTLINE")
          expect(result.output.length).toBeLessThanOrEqual(2_400)
          expect(SkillContext.isLoaded("large-skill")).toBe(false)
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("execute returns skill content block with files", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        const skillDir = path.join(dir, ".cyberstrike", "skill", "tool-skill")
        await Bun.write(
          path.join(skillDir, "SKILL.md"),
          `---
name: tool-skill
description: Skill for tool tests.
owasp_id: T1078.004
---

# Tool Skill

Use this skill.
`,
        )
        await Bun.write(path.join(skillDir, "scripts", "demo.txt"), "demo")
        await fs.mkdir(path.join(skillDir, "reference"), { recursive: true })
        for (let index = 0; index < 15; index++) {
          await Bun.write(path.join(skillDir, "reference", "part-" + index + ".md"), "reference " + index)
        }
      },
    })

    const home = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path

    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const tool = await SkillTool.init()
          const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
          const ctx: Tool.Context = {
            ...baseCtx,
            ask: async (req) => {
              requests.push(req)
            },
          }

          const result = await tool.execute({ action: "load", name: "T1078.004" }, ctx)
          expect(SkillContext.isLoaded("tool-skill")).toBe(true)
          SkillContext.unload("tool-skill")
          const dir = path.join(tmp.path, ".cyberstrike", "skill", "tool-skill")
          const file = path.resolve(dir, "scripts", "demo.txt")

          expect(requests.length).toBe(1)
          expect(requests[0].permission).toBe("skill")
          expect(requests[0].patterns).toContain("tool-skill")
          expect(requests[0].always).toContain("tool-skill")

          expect(result.metadata.dir).toBe(dir)
          expect(result.output).toContain(`<skill_content name="tool-skill" verified="unverified">`)
          expect(result.output).toContain(`Base directory for this skill: ${pathToFileURL(dir).href}`)
          expect(result.output).toContain(`<file>${file}</file>`)
          expect(result.output).toContain(path.resolve(dir, "reference", "part-0.md"))
          expect(result.output).toContain(path.resolve(dir, "reference", "part-14.md"))
          expect(result.output).not.toContain("file list is sampled")
        },
      })
    } finally {
      process.env.CYBERSTRIKE_TEST_HOME = home
    }
  })

  test("discovers and loads nested src-hunter payloader skills with exact runtime reference paths", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        const skillRoot = path.join(dir, ".cyberstrike", "skill")
        const payloaderDir = path.join(skillRoot, "payloader")
        const webDir = path.join(payloaderDir, "by-category", "web")
        const playbooksDir = path.join(skillRoot, "playbooks")
        const h1Dir = path.join(skillRoot, "h1-reports", "by-weakness")

        await Bun.write(
          path.join(payloaderDir, "SKILL.md"),
          [
            "---",
            "name: payloader",
            "description: On-demand payload reference router for src-hunter.",
            "category: web-security",
            'tags: ["src-hunter", "payloader", "payload-reference"]',
            "---",
            "",
            "# Payloader router",
            "Use the returned Base directory and skill_files to read local reference content.",
            "",
          ].join("\n"),
        )
        await Bun.write(path.join(payloaderDir, "index.md"), "# Payload index\n")

        await Bun.write(
          path.join(playbooksDir, "SKILL.md"),
          [
            "---",
            "name: playbooks",
            "description: Routes evidence-backed bug-bounty hypotheses to local playbook references.",
            'chains_with: ["payloader", "hackerone-disclosed-reports"]',
            'tags: ["src-hunter", "playbooks", "bug-bounty"]',
            "---",
            "",
            "# Playbook router",
            "Read the exact local playbook before designing a test.",
            "",
          ].join("\n"),
        )
        await Bun.write(path.join(playbooksDir, "00-index.md"), "# Playbook index\n")
        await Bun.write(path.join(playbooksDir, "sqli.md"), "# SQLi reference\nPLAYBOOK_RUNTIME_READ_MARKER\n")

        await Bun.write(
          path.join(h1Dir, "SKILL.md"),
          [
            "---",
            "name: hackerone-disclosed-reports",
            "description: Routes to relevant public disclosed report examples.",
            'tags: ["hackerone", "disclosed-reports", "bug-bounty"]',
            "---",
            "",
            "# HackerOne reports router",
            "Read the index and only the relevant weakness file.",
            "",
          ].join("\n"),
        )
        await Bun.write(path.join(h1Dir, "index.md"), "# H1 report index\n")
        await Bun.write(path.join(h1Dir, "sql-injection.md"), "# SQL injection case reference\nH1_RUNTIME_READ_MARKER\n")

        await Bun.write(
          path.join(webDir, "SKILL.md"),
          [
            "---",
            "name: src-hunter-payloader-web",
            "description: Routes evidence-backed web hypotheses to local payload category files.",
            "category: web-security",
            'tags: ["src-hunter", "payloader", "payload-reference", "xss", "sqli"]',
            "---",
            "",
            "# Web payload routing",
            "Read the exact category file before choosing a test.",
            "",
          ].join("\n"),
        )
        await Bun.write(
          path.join(webDir, "xss跨站脚本.md"),
          "# XSS reference\nPAYLOADER_RUNTIME_READ_MARKER\n",
        )
      },
    })

    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          try {
            const tool = await SkillTool.init()
            const ctx: Tool.Context = { ...baseCtx, ask: async () => {} }

            const search = await tool.execute(
              { action: "search", query: "src-hunter-payloader-web", limit: 10 },
              ctx,
            )
            expect(search.output).toContain("src-hunter-payloader-web")
            expect(search.output).toContain("Search Results")

            const loaded = await tool.execute(
              { action: "load", name: "src-hunter-payloader-web" },
              ctx,
            )
            const webDir = path.join(tmp.path, ".cyberstrike", "skill", "payloader", "by-category", "web")
            const reference = path.resolve(webDir, "xss跨站脚本.md")
            expect(loaded.title).toBe("Loaded skill: src-hunter-payloader-web")
            expect(loaded.output).toContain("Read the exact category file before choosing a test.")
            expect(loaded.output).toContain(`Base directory for this skill: ${pathToFileURL(webDir).href}`)
            expect(loaded.output).toContain(`<file>${reference}</file>`)
            expect(loaded.output).not.toContain("PAYLOADER_RUNTIME_READ_MARKER")
            expect(await Bun.file(reference).text()).toContain("PAYLOADER_RUNTIME_READ_MARKER")
            expect(SkillContext.isLoaded("src-hunter-payloader-web")).toBe(true)

            const rootLoaded = await tool.execute({ action: "load", name: "payloader" }, ctx)
            const rootDir = path.join(tmp.path, ".cyberstrike", "skill", "payloader")
            const indexPath = path.resolve(rootDir, "index.md")
            expect(rootLoaded.title).toBe("Loaded skill: payloader")
            expect(rootLoaded.output).toContain(`<file>${indexPath}</file>`)
            expect(await Bun.file(indexPath).text()).toContain("Payload index")

            const playbooksLoaded = await tool.execute({ action: "load", name: "playbooks" }, ctx)
            const playbookBase = path.join(tmp.path, ".cyberstrike", "skill", "playbooks")
            const playbookIndex = path.resolve(playbookBase, "00-index.md")
            const playbookReference = path.resolve(playbookBase, "sqli.md")
            expect(playbooksLoaded.title).toBe("Loaded skill: playbooks")
            expect(playbooksLoaded.output).toContain(`Base directory for this skill: ${pathToFileURL(playbookBase).href}`)
            expect(playbooksLoaded.output).toContain(`<file>${playbookIndex}</file>`)
            expect(playbooksLoaded.output).toContain(`<file>${playbookReference}</file>`)
            expect(await Bun.file(playbookIndex).text()).toContain("Playbook index")
            expect(await Bun.file(playbookReference).text()).toContain("PLAYBOOK_RUNTIME_READ_MARKER")

            const h1Loaded = await tool.execute({ action: "load", name: "hackerone-disclosed-reports" }, ctx)
            const h1Base = path.join(tmp.path, ".cyberstrike", "skill", "h1-reports", "by-weakness")
            const h1Index = path.resolve(h1Base, "index.md")
            const h1Reference = path.resolve(h1Base, "sql-injection.md")
            expect(h1Loaded.title).toBe("Loaded skill: hackerone-disclosed-reports")
            expect(h1Loaded.output).toContain(`Base directory for this skill: ${pathToFileURL(h1Base).href}`)
            expect(h1Loaded.output).toContain(`<file>${h1Index}</file>`)
            expect(h1Loaded.output).toContain(`<file>${h1Reference}</file>`)
            expect(await Bun.file(h1Index).text()).toContain("H1 report index")
            expect(await Bun.file(h1Reference).text()).toContain("H1_RUNTIME_READ_MARKER")
          } finally {
            SkillContext.clear()
          }
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("execute resolves directory aliases when metadata uses another name", async () => {
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

DYNAMIC_SKILL_ALIAS_REGRESSION_MARKER
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
          const tool = await SkillTool.init()
          const result = await tool.execute(
            { action: "load", name: "wstg-authz-04" },
            { ...baseCtx, ask: async () => {} },
          )
          expect(result.title).toBe("Loaded skill: readable-authorization-guide")
          expect(result.output).toContain("DYNAMIC_SKILL_ALIAS_REGRESSION_MARKER")
          expect(result.metadata.name).toBe("readable-authorization-guide")
          SkillContext.unload("readable-authorization-guide")
        },
      })
    } finally {
      if (home === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = home
    }
  })

  test("unload resolves the same directory aliases accepted by load", async () => {
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
          const tool = await SkillTool.init()
          const ctx: Tool.Context = { ...baseCtx, ask: async () => {} }
          await tool.execute({ action: "load", name: "wstg-authz-04" }, ctx)
          expect(SkillContext.isLoaded("readable-authorization-guide")).toBe(true)
          const result = await tool.execute({ action: "unload", name: "wstg-authz-04" }, ctx)
          expect(result.title).toBe("Unloaded: readable-authorization-guide")
          expect(SkillContext.isLoaded("readable-authorization-guide")).toBe(false)
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("skill caches refresh after an instance is disposed and recreated at the same path", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        const skillDir = path.join(dir, ".cyberstrike", "skill", "refreshable-skill")
        await fs.mkdir(skillDir, { recursive: true })
        await Bun.write(
          path.join(skillDir, "SKILL.md"),
          `---
name: refreshable-skill
description: Old description.
tags: ["old-tag"]
---

OLD_SKILL_CATALOG_MARKER
`,
        )
      },
    })

    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    process.env.CYBERSTRIKE_TEST_HOME = tmp.path
    const tool = await SkillTool.init()
    const ctx: Tool.Context = { ...baseCtx, ask: async () => {} }
    try {
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const listing = await tool.execute({ action: "list" }, ctx)
          expect(listing.output).toContain("Old description.")
          const loaded = await tool.execute({ action: "load", name: "refreshable-skill" }, ctx)
          expect(loaded.output).toContain("OLD_SKILL_CATALOG_MARKER")
          expect(SkillContext.active()).toContain("refreshable-skill")
          expect(SkillIndex.byTag("old-tag").map((skill) => skill.name)).toContain("refreshable-skill")
          await Instance.dispose()
        },
      })

      await Bun.write(
        path.join(tmp.path, ".cyberstrike", "skill", "refreshable-skill", "SKILL.md"),
        `---
name: refreshable-skill
description: Updated description.
tags: ["new-tag"]
---

NEW_SKILL_CATALOG_MARKER
`,
      )

      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const listing = await tool.execute({ action: "list" }, ctx)
          expect(listing.output).toContain("Updated description.")
          expect(listing.output).not.toContain("Old description.")
          expect(SkillIndex.byTag("new-tag").map((skill) => skill.name)).toContain("refreshable-skill")
          expect(SkillIndex.byTag("old-tag")).toEqual([])
          const loaded = await tool.execute({ action: "load", name: "refreshable-skill" }, ctx)
          expect(loaded.output).toContain("NEW_SKILL_CATALOG_MARKER")
          expect(loaded.output).not.toContain("OLD_SKILL_CATALOG_MARKER")
          expect(SkillContext.active()).toEqual(["refreshable-skill"])
          expect(SkillContext.isLoaded("refreshable-skill")).toBe(true)
          await Instance.dispose()
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

  test("skill remains loaded when companion-file enumeration fails", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        const skillDir = path.join(dir, ".cyberstrike", "skill", "listing-failure-skill")
        await Bun.write(
          path.join(skillDir, "SKILL.md"),
          `---
name: listing-failure-skill
description: Skill whose companion listing fails.
---
# Listing Failure Skill
The skill body must still load.
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
          // Prime the metadata catalog, then inject a failure only for the
          // companion-file subprocess. SKILL.md remains readable so this tests
          // best-effort enumeration instead of a missing skill source.
          const skillDir = path.join(tmp.path, ".cyberstrike", "skill", "listing-failure-skill")
          expect((await (await import("../../src/skill")).Skill.all()).some((skill) => skill.name === "listing-failure-skill")).toBe(true)

          const tool = await SkillTool.init()
          const ctx: Tool.Context = {
            ...baseCtx,
            ask: async () => {},
          }
          const originalSpawn = Bun.spawn.bind(Bun)
          const injectedSpawn = ((command: string[], options?: any) => {
            if (options?.cwd === skillDir) throw new Error("Injected companion-file listing failure")
            return originalSpawn(command, options)
          }) as typeof Bun.spawn
          const spawnSpy = spyOn(Bun, "spawn").mockImplementation(injectedSpawn)
          try {
            const result = await tool.execute({ action: "load", name: "listing-failure-skill" }, ctx)

            expect(SkillContext.isLoaded("listing-failure-skill")).toBe(true)
            expect(result.title).toBe("Loaded skill: listing-failure-skill")
            expect(result.output).toContain("The skill body must still load.")
            expect(result.output).toContain("<file-list-unavailable>")
            SkillContext.unload("listing-failure-skill")
          } finally {
            spawnSpy.mockRestore()
          }
        },
      })
    } finally {
      process.env.CYBERSTRIKE_TEST_HOME = home
    }
  })

  test("curated SRC-Hunter references load through SkillTool and every declared file is readable", async () => {
    const repoRoot = path.resolve(import.meta.dir, "../../../..")
    const skillRoot = path.join(repoRoot, ".cyberstrike", "skill")
    const manifest = JSON.parse(await Bun.file(path.join(skillRoot, "index.json")).text()) as {
      skills: Array<{ name: string; files?: string[] }>
    }
    const entries = manifest.skills.filter((entry) =>
      entry.name.startsWith("src-hunter-") || entry.name === "community-tool-selection" || entry.name === "recon-methodology",
    )
    expect(entries.length).toBeGreaterThanOrEqual(8)

    const previousHome = process.env.CYBERSTRIKE_TEST_HOME
    delete process.env.CYBERSTRIKE_TEST_HOME
    try {
      await Instance.provide({
        directory: repoRoot,
        fn: async () => {
          const skillTool = await SkillTool.init()
          const readTool = await ReadTool.init()
          const ctx: Tool.Context = { ...baseCtx, agent: "cyberstrike", ask: async () => {} }

          for (const entry of entries) {
            const loaded = await skillTool.execute({ action: "load", name: entry.name }, ctx)
            expect(loaded.title).toBe("Loaded skill: " + entry.name)
            expect(loaded.output).toContain("<skill_content name=\"" + entry.name + "\"")
            expect(SkillContext.isLoaded(entry.name)).toBe(true)

            const baseMatch = loaded.output.match(/^Base directory for this skill: (file:\/\/[^\r\n]+)/m)
            expect(baseMatch, entry.name + " must return its runtime Base directory").toBeDefined()
            const base = path.resolve(fileURLToPath(baseMatch![1]))

            for (const relative of entry.files ?? []) {
              const filepath = path.resolve(base, relative)
              expect(
                filepath === path.join(base, "SKILL.md") || filepath.startsWith(base + path.sep),
                entry.name + " reference path must remain inside its skill directory",
              ).toBe(true)

              const read = await readTool.execute({ filePath: filepath }, ctx)
              expect(read.output, entry.name + " must allow reading " + relative).toContain("<type>file</type>")
              expect(read.output, entry.name + " reference must contain readable text: " + relative).toContain("<content>")
              expect(read.output.trim().length).toBeGreaterThan(40)

              if (relative !== "SKILL.md") {
                expect(loaded.output).toContain("<file>" + filepath + "</file>")
              }
            }
            SkillContext.unload(entry.name)
          }
        },
      })
    } finally {
      if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
      else process.env.CYBERSTRIKE_TEST_HOME = previousHome
    }
  })

})
