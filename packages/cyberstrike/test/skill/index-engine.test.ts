import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { SkillIndex } from "../../src/skill/index-engine"
import { SkillContext } from "../../src/skill/context"
import { tmpdir } from "../fixture/fixture"

test("resolves exact technique aliases and audits kill-chain and prerequisite references", async () => {
  await using tmp = await tmpdir({ git: true })
  const priorTestHome = process.env.CYBERSTRIKE_TEST_HOME
  process.env.CYBERSTRIKE_TEST_HOME = tmp.path

  const addSkill = async (name: string, metadata: string) => {
    const dir = path.join(tmp.path, ".cyberstrike", "skill", name)
    await fs.mkdir(dir, { recursive: true })
    await Bun.write(
      path.join(dir, "SKILL.md"),
      `---
name: ${name}
description: ${name} test skill
${metadata}
---
Skill body for ${name}.
`,
    )
  }

  try {
    await addSkill(
      "aws-postexploit",
      'tech_stack: ["aws"]\nchains_with: ["T1078.004", "T1552.005"]\nprerequisites: ["T1078.004", "T1552.005"]',
    )
    await addSkill(
      "T1078.004_cloud-accounts",
      'tags: ["t1078.004"]\ncwe_ids: ["CWE-693"]\ntech_stack: ["cloud"]',
    )
    await addSkill(
      "T1552.005_cloud-instance-metadata-api",
      'tags: ["t1552.005"]\ncwe_ids: ["CWE-522"]\ntech_stack: ["aws"]',
    )
    await addSkill("target-workflow", 'chains_with: ["aws-postexploit"]')
    await addSkill("triage-validation", 'tags: ["triage"]')
    await addSkill("prefixed-workflow", 'chains_with: ["attack-triage-validation"]')
    await addSkill(
      "external-control-metadata",
      'chains_with: ["PE-18"]\\nprerequisites: ["An explicitly authorized test account is required"]',
    )

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        await SkillIndex.rebuild()

        expect(SkillIndex.resolveReference("T1078.004")).toBe("T1078.004_cloud-accounts")
        expect(SkillIndex.resolveReference("T1552.005")).toBe("T1552.005_cloud-instance-metadata-api")
        expect(SkillIndex.resolveReference("AWS-POSTEXPLOIT")).toBe("aws-postexploit")
        expect(SkillIndex.resolveReference("attack-triage-validation")).toBe("triage-validation")
        expect(SkillIndex.chainsFrom("prefixed-workflow").map((item) => item.target)).toEqual(["triage-validation"])
        expect(SkillIndex.chainsFrom("external-control-metadata")).toEqual([])
        expect(SkillIndex.validateReferences()).toEqual([])
        expect(SkillIndex.chainsFrom("target-workflow").map((item) => item.target)).toEqual(["aws-postexploit"])
        expect(SkillIndex.chainsFrom("aws-postexploit").map((item) => item.target)).toEqual([
          "T1078.004_cloud-accounts",
          "T1552.005_cloud-instance-metadata-api",
        ])
        expect(SkillIndex.prerequisitesFor("aws-postexploit")).toEqual([
          "T1078.004_cloud-accounts",
          "T1552.005_cloud-instance-metadata-api",
        ])
        expect(SkillIndex.validateReferences()).toEqual([])

        const cweSuggestions = SkillContext.suggest([
          { skill_id: "no-existing-chain", cwe_id: "CWE-522", severity: "critical" },
        ])
        expect(cweSuggestions).toContainEqual({
          name: "T1552.005_cloud-instance-metadata-api",
          reason: "matches CWE: CWE-522",
          priority: "high",
        })

        const chainSuggestions = SkillContext.suggest([{ skill_id: "target-workflow" }])
        const prerequisiteIndex = chainSuggestions.findIndex(
          (item) => item.name === "T1078.004_cloud-accounts",
        )
        const dependentIndex = chainSuggestions.findIndex((item) => item.name === "aws-postexploit")
        expect(prerequisiteIndex).toBeGreaterThanOrEqual(0)
        expect(dependentIndex).toBeGreaterThan(prerequisiteIndex)
        expect(chainSuggestions.find((item) => item.name === "T1078.004_cloud-accounts")?.reason).toBe(
          "prerequisite for aws-postexploit",
        )
      },
    })
  } finally {
    if (priorTestHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
    else process.env.CYBERSTRIKE_TEST_HOME = priorTestHome
  }
})

test("full repository skill catalog has no unresolved chain or prerequisite references", async () => {
  const repoRoot = path.resolve(import.meta.dir, "../../../..")
  const previousTestHome = process.env.CYBERSTRIKE_TEST_HOME
  delete process.env.CYBERSTRIKE_TEST_HOME

  try {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        await SkillIndex.rebuild()
        expect(SkillIndex.validateReferences()).toEqual([])
      },
    })
  } finally {
    if (previousTestHome === undefined) delete process.env.CYBERSTRIKE_TEST_HOME
    else process.env.CYBERSTRIKE_TEST_HOME = previousTestHome
  }
}, 60000)
