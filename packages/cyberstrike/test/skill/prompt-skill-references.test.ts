import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { Skill } from "../../src/skill/skill"

test("every exact skill load referenced by an agent prompt exists and can be hydrated", async () => {
  const repoRoot = path.resolve(import.meta.dir, "../../../..")
  const packageRoot = path.resolve(import.meta.dir, "../..")
  const promptRoot = path.join(packageRoot, "src", "agent", "prompt")
  // Use Node's directory traversal instead of Bun.Glob's absolute-path mode.
  // On the CI runner that mode yields a NUL-suffixed cwd and fs.readFile fails
  // before the referenced-skill checks can run.
  async function listPromptFiles(directory: string): Promise<string[]> {
    const entries = await fs.readdir(directory, { withFileTypes: true })
    const nested = await Promise.all(
      entries.map(async (entry) => {
        const fullPath = path.join(directory, entry.name)
        if (entry.isDirectory()) return listPromptFiles(fullPath)
        return entry.isFile() && entry.name.endsWith(".txt") ? [fullPath] : []
      }),
    )
    return nested.flat()
  }
  const promptFiles = await listPromptFiles(promptRoot)
  const references = new Map<string, string[]>()
  const pattern = /skill\(\{\s*action:\s*["'](?:load|outline)["']\s*,\s*name:\s*["']([^"']+)["']/g

  for (const file of promptFiles) {
    const source = await fs.readFile(file, "utf8")
    for (const match of source.matchAll(pattern)) {
      const name = match[1]!
      // Angle-bracket names are prompt templates (for example,
      // "<exact-name-from-search>"), not literal skills to hydrate.
      if (/^<[^<>]+>$/.test(name)) continue
      const locations = references.get(name) ?? []
      locations.push(path.relative(repoRoot, file))
      references.set(name, locations)
    }
  }

  // A prompt tree with only dynamic search examples is valid; validate every
  // literal canonical skill name that is actually embedded in a prompt.
  expect(promptFiles.length).toBeGreaterThan(0)
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
