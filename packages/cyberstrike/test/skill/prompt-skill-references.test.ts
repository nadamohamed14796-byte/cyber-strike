import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { Skill } from "../../src/skill/skill"

test("every exact skill load referenced by an agent prompt exists and can be hydrated", async () => {
  const repoRoot = path.resolve(import.meta.dir, "../../../..")
  const promptRoot = path.join(repoRoot, "src", "agent", "prompt")
  const promptFiles = await Array.fromAsync(
    new Bun.Glob("**/*.txt").scan({ cwd: promptRoot, absolute: true, onlyFiles: true }),
  )
  const references = new Map<string, string[]>()
  const pattern = /skill\(\{\s*action:\s*["'](?:load|outline)["']\s*,\s*name:\s*["']([^"']+)["']/g

  for (const file of promptFiles) {
    const source = await fs.readFile(file, "utf8")
    for (const match of source.matchAll(pattern)) {
      const name = match[1]!
      const locations = references.get(name) ?? []
      locations.push(path.relative(repoRoot, file))
      references.set(name, locations)
    }
  }

  expect(references.size).toBeGreaterThan(0)
  await Instance.provide({
    directory: repoRoot,
    fn: async () => {
      const missing: string[] = []
      for (const [name, locations] of references) {
        const skill = await Skill.get(name)
        if (!skill?.content.trim()) missing.push(name + " (referenced by " + locations.join(", ") + ")")
      }
      expect(missing).toEqual([])
    },
  })
}, 60000)
