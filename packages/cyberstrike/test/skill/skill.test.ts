import { test, expect } from "bun:test"
import { Skill } from "../../src/skill"
import { SkillContext } from "../../src/skill/context"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"
import path from "path"
import fs from "fs/promises"

async function createGlobalSkill(homeDir: string) {
  const skillDir = path.join(homeDir, ".claude", "skills", "global-test-skill")
  await fs.mkdir(skillDir, { recursive: true })
  await Bun.write(
    path.join(skillDir, "SKILL.md"),
    `---
name: global-test-skill
description: A global skill from ~/.claude/skills for testing.
---

# Global Test Skill

This skill is loaded from the global home directory.
`,
  )
}

test("discovers skills from .cyberstrike/skill/ directory", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".cyberstrike", "skill", "test-skill")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `---
name: test-skill
description: A test skill for verification.
---

# Test Skill

Instructions here.
`,
      )
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const skills = await Skill.all()
      expect(skills.length).toBe(1)
      const testSkill = skills.find((s) => s.name === "test-skill")
      expect(testSkill).toBeDefined()
      expect(testSkill!.description).toBe("A test skill for verification.")
      expect("content" in testSkill!).toBe(false)
      const hydrated = await Skill.get("test-skill")
      expect(hydrated?.content).toContain("Instructions here.")
      // Models sometimes change identifier casing; only a unique exact-name
      // match ignoring case should be accepted (never fuzzy substring matching).
      expect((await Skill.get("TEST-SKILL"))?.name).toBe("test-skill")
      expect(await Skill.get("test-ski")).toBeUndefined()
      expect(testSkill!.location).toContain("skill/test-skill/SKILL.md")
    },
  })
})

test("returns skill directories from Skill.dirs", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".cyberstrike", "skill", "dir-skill")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `---
name: dir-skill
description: Skill for dirs test.
---

# Dir Skill
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
        const dirs = await Skill.dirs()
        const skillDir = path.join(tmp.path, ".cyberstrike", "skill", "dir-skill")
        expect(dirs).toContain(skillDir)
        expect(dirs.length).toBe(1)
      },
    })
  } finally {
    process.env.CYBERSTRIKE_TEST_HOME = home
  }
})

test("discovers multiple skills from .cyberstrike/skill/ directory", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir1 = path.join(dir, ".cyberstrike", "skill", "skill-one")
      const skillDir2 = path.join(dir, ".cyberstrike", "skill", "skill-two")
      await Bun.write(
        path.join(skillDir1, "SKILL.md"),
        `---
name: skill-one
description: First test skill.
---

# Skill One
`,
      )
      await Bun.write(
        path.join(skillDir2, "SKILL.md"),
        `---
name: skill-two
description: Second test skill.
---

# Skill Two
`,
      )
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const skills = await Skill.all()
      expect(skills.length).toBe(2)
      expect(skills.find((s) => s.name === "skill-one")).toBeDefined()
      expect(skills.find((s) => s.name === "skill-two")).toBeDefined()
    },
  })
})

test("skips skills with missing frontmatter", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".cyberstrike", "skill", "no-frontmatter")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `# No Frontmatter

Just some content without YAML frontmatter.
`,
      )
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const skills = await Skill.all()
      expect(skills).toEqual([])
    },
  })
})

test("project-local CyberStrike skills outrank same-name global-home skills", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const globalSkill = path.join(dir, ".cyberstrike", "skill", "precedence-skill")
      const projectDir = path.join(dir, "cyberstrike-test-project")
      const projectSkill = path.join(projectDir, ".cyberstrike", "skill", "precedence-skill")

      await Bun.write(
        path.join(globalSkill, "SKILL.md"),
        `---
name: precedence-skill
description: Global copy that must not override a project skill.
---

# Global Copy

GLOBAL_VERSION_MARKER
`,
      )
      await Bun.write(
        path.join(projectSkill, "SKILL.md"),
        `---
name: precedence-skill
description: Project copy has higher precedence.
---

# Project Copy

PROJECT_VERSION_MARKER
`,
      )
    },
  })

  const previousHome = process.env.CYBERSTRIKE_TEST_HOME
  process.env.CYBERSTRIKE_TEST_HOME = tmp.path
  try {
    await Instance.provide({
      directory: path.join(tmp.path, "cyberstrike-test-project"),
      fn: async () => {
        const skill = await Skill.get("precedence-skill")
        expect(skill).toBeDefined()
        expect(skill!.content).toContain("PROJECT_VERSION_MARKER")
        expect(skill!.content).not.toContain("GLOBAL_VERSION_MARKER")
        expect(skill!.location).toContain(
          path.join("cyberstrike-test-project", ".cyberstrike", "skill", "precedence-skill", "SKILL.md"),
        )
      },
    })
  } finally {
    if (previousHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
    else process.env.CYBERSTRIKE_TEST_HOME = previousHome
  }
})

test("discovers skills from .claude/skills/ directory", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".claude", "skills", "claude-skill")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
      )
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const skills = await Skill.all()
      expect(skills.length).toBe(1)
      const claudeSkill = skills.find((s) => s.name === "claude-skill")
      expect(claudeSkill).toBeDefined()
      expect(claudeSkill!.location).toContain(".claude/skills/claude-skill/SKILL.md")
    },
  })
})

test("discovers global skills from ~/.claude/skills/ directory", async () => {
  await using tmp = await tmpdir({ git: true })

  const originalHome = process.env.CYBERSTRIKE_TEST_HOME
  process.env.CYBERSTRIKE_TEST_HOME = tmp.path

  try {
    await createGlobalSkill(tmp.path)
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const skills = await Skill.all()
        expect(skills.length).toBe(1)
        expect(skills[0].name).toBe("global-test-skill")
        expect(skills[0].description).toBe("A global skill from ~/.claude/skills for testing.")
        expect(skills[0].location).toContain(".claude/skills/global-test-skill/SKILL.md")
      },
    })
  } finally {
    process.env.CYBERSTRIKE_TEST_HOME = originalHome
  }
})

test("returns empty array when no skills exist", async () => {
  await using tmp = await tmpdir({ git: true })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const skills = await Skill.all()
      expect(skills).toEqual([])
    },
  })
})

test("discovers skills from .agents/skills/ directory", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const skillDir = path.join(dir, ".agents", "skills", "agent-skill")
      await Bun.write(
        path.join(skillDir, "SKILL.md"),
        `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
      )
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const skills = await Skill.all()
      expect(skills.length).toBe(1)
      const agentSkill = skills.find((s) => s.name === "agent-skill")
      expect(agentSkill).toBeDefined()
      expect(agentSkill!.location).toContain(".agents/skills/agent-skill/SKILL.md")
    },
  })
})

test("discovers global skills from ~/.agents/skills/ directory", async () => {
  await using tmp = await tmpdir({ git: true })

  const originalHome = process.env.CYBERSTRIKE_TEST_HOME
  process.env.CYBERSTRIKE_TEST_HOME = tmp.path

  try {
    const skillDir = path.join(tmp.path, ".agents", "skills", "global-agent-skill")
    await fs.mkdir(skillDir, { recursive: true })
    await Bun.write(
      path.join(skillDir, "SKILL.md"),
      `---
name: global-agent-skill
description: A global skill from ~/.agents/skills for testing.
---

# Global Agent Skill

This skill is loaded from the global home directory.
`,
    )

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const skills = await Skill.all()
        expect(skills.length).toBe(1)
        expect(skills[0].name).toBe("global-agent-skill")
        expect(skills[0].description).toBe("A global skill from ~/.agents/skills for testing.")
        expect(skills[0].location).toContain(".agents/skills/global-agent-skill/SKILL.md")
      },
    })
  } finally {
    process.env.CYBERSTRIKE_TEST_HOME = originalHome
  }
})

test("discovers skills from both .claude/skills/ and .agents/skills/", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const claudeDir = path.join(dir, ".claude", "skills", "claude-skill")
      const agentDir = path.join(dir, ".agents", "skills", "agent-skill")
      await Bun.write(
        path.join(claudeDir, "SKILL.md"),
        `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
      )
      await Bun.write(
        path.join(agentDir, "SKILL.md"),
        `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
      )
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const skills = await Skill.all()
      expect(skills.length).toBe(2)
      expect(skills.find((s) => s.name === "claude-skill")).toBeDefined()
      expect(skills.find((s) => s.name === "agent-skill")).toBeDefined()
    },
  })
})

test("properly resolves directories that skills live in", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const cyberstrikeSkillDir = path.join(dir, ".cyberstrike", "skill", "agent-skill")
      const cyberstrikeSkillsDir = path.join(dir, ".cyberstrike", "skills", "agent-skill")
      const claudeDir = path.join(dir, ".claude", "skills", "claude-skill")
      const agentDir = path.join(dir, ".agents", "skills", "agent-skill")
      await Bun.write(
        path.join(claudeDir, "SKILL.md"),
        `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
      )
      await Bun.write(
        path.join(agentDir, "SKILL.md"),
        `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
      )
      await Bun.write(
        path.join(cyberstrikeSkillDir, "SKILL.md"),
        `---
name: cyberstrike-skill
description: A skill in the .cyberstrike/skill directory.
---

# CyberStrike Skill
`,
      )
      await Bun.write(
        path.join(cyberstrikeSkillsDir, "SKILL.md"),
        `---
name: cyberstrike-skill
description: A skill in the .cyberstrike/skills directory.
---

# CyberStrike Skill
`,
      )
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const dirs = await Skill.dirs()
      expect(dirs.length).toBe(4)
    },
  })
})


test("representative skills in the full catalog can be loaded into context", async () => {
  const repoRoot = path.resolve(import.meta.dir, "../../../..")
  const previousTestHome = process.env.CYBERSTRIKE_TEST_HOME
  delete process.env.CYBERSTRIKE_TEST_HOME

  try {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        SkillContext.clear()
        try {
          const skills = await Skill.all()
          expect(skills.length).toBeGreaterThan(0)
          const selected = [
            "target-workspace-workflow",
            "community-tool-selection",
            "recon-methodology",
            "attack-javascript-analysis",
            "wstg-authz-04",
          ]
          for (const name of selected) {
            expect(skills.some((skill) => skill.name === name), name + " should exist in the catalog").toBe(true)
            const loaded = await SkillContext.load(name)
            if (loaded === undefined) throw new Error(name + " failed to load into skill context")
            expect(loaded.trim(), name + " should load non-empty content").not.toBe("")
            expect(SkillContext.isLoaded(name), name + " should be marked loaded").toBe(true)
            expect(SkillContext.unload(name), name + " should unload cleanly").toBe(true)
          }
        } finally {
          SkillContext.clear()
        }
      },
    })
  } finally {
    if (previousTestHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
    else process.env.CYBERSTRIKE_TEST_HOME = previousTestHome
  }
}, 60000)


test("portable release skill catalog takes precedence when the source checkout is unavailable", () => {
  const dataDirectory = path.join("/", "home", "test", ".local", "share", "cyberstrike")
  const executablePath = path.join("/", "opt", "cyberstrike", "bin", "cyberstrike")
  const portable = Skill.runtimeSkillSources(dataDirectory, executablePath, false)
  expect(portable).toEqual([
    { directory: path.join(dataDirectory, "skill"), priority: -1 },
    { directory: path.join(path.dirname(executablePath), "skill"), priority: 1 },
  ])

  const sourceCheckout = Skill.runtimeSkillSources(dataDirectory, executablePath, true)
  expect(sourceCheckout[1].priority).toBeLessThan(sourceCheckout[0].priority)
})

test("skill source discovery does not scan an identical catalog path twice", () => {
  const executablePath = path.join("/", "opt", "cyberstrike", "bin", "cyberstrike")
  expect(
    Skill.runtimeSkillSources(path.dirname(executablePath), executablePath, false),
  ).toEqual([{ directory: path.join(path.dirname(executablePath), "skill"), priority: -1 }])
})
