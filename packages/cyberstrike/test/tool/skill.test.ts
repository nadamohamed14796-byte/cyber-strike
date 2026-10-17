import { describe, expect, test } from "bun:test"
import path from "path"
import fs from "node:fs/promises"
import { pathToFileURL } from "url"
import type { PermissionNext } from "../../src/permission/next"
import type { Tool } from "../../src/tool/tool"
import { Instance } from "../../src/project/instance"
import { SkillTool } from "../../src/tool/skill"
import { SkillContext } from "../../src/skill/context"
import { SkillIndex } from "../../src/skill/index-engine"
import { tmpdir } from "../fixture/fixture"

const baseCtx: Omit<Tool.Context, "ask"> = {
  sessionID: "test",
  messageID: "",
  callID: "",
  agent: "build",
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

  test("description shows skill count", async () => {
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
          // Prime the skill catalog, then remove only its directory. The cached
          // SKILL.md remains available while Ripgrep.files must fail on ENOENT.
          const skillDir = path.join(tmp.path, ".cyberstrike", "skill", "listing-failure-skill")
          expect((await (await import("../../src/skill")).Skill.all()).some((skill) => skill.name === "listing-failure-skill")).toBe(true)
          await fs.rm(skillDir, { recursive: true, force: true })

          const tool = await SkillTool.init()
          const ctx: Tool.Context = {
            ...baseCtx,
            ask: async () => {},
          }
          const result = await tool.execute({ action: "load", name: "listing-failure-skill" }, ctx)

          expect(SkillContext.isLoaded("listing-failure-skill")).toBe(true)
          expect(result.title).toBe("Loaded skill: listing-failure-skill")
          expect(result.output).toContain("The skill body must still load.")
          expect(result.output).toContain("<file-list-unavailable>")
          SkillContext.unload("listing-failure-skill")
        },
      })
    } finally {
      process.env.CYBERSTRIKE_TEST_HOME = home
    }
  })

})
