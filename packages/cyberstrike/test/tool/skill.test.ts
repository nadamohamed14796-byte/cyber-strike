import { describe, expect, test } from "bun:test"
import path from "path"
import { pathToFileURL } from "url"
import type { PermissionNext } from "../../src/permission/next"
import type { Tool } from "../../src/tool/tool"
import { Instance } from "../../src/project/instance"
import { SkillTool } from "../../src/tool/skill"
import { SkillContext } from "../../src/skill/context"
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

  test("list and search paginate large skill catalogs", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        for (const name of ["tool-skill-a", "tool-skill-b", "tool-skill-c"]) {
          const skillDir = path.join(dir, ".cyberstrike", "skill", name)
          await Bun.write(
            path.join(skillDir, "SKILL.md"),
            `---
name: ${name}
description: Pagination fixture skill.
---

# ${name}
`,
          )
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
        },
      })
    } finally {
      process.env.CYBERSTRIKE_TEST_HOME = home
    }
  })
})
