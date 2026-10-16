import { describe, expect, test } from "bun:test"
import path from "path"
import fs from "node:fs/promises"
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
