#!/usr/bin/env bun
// Refresh metadata for the curated publishing registry.
// Usage: bun run packages/cyberstrike/script/generate-registry.ts
// The checked-in index.json is the allowlist: this script must not silently publish every
// framework/vendor skill discovered by the runtime loader.
import path from "path"
import { existsSync, readdirSync } from "fs"
import { SkillSigning } from "../src/skill/signing"

const root = path.resolve(import.meta.dir, "../../..")
const skillDir = path.join(root, ".cyberstrike", "skill")
const indexPath = path.join(skillDir, "index.json")

type RegistryEntry = {
  name: string
  description: string
  category?: string
  owasp_id?: string
  verified: SkillSigning.VerificationStatus
  tags: string[]
  tech_stack: string[]
  cwe_ids: string[]
  files: string[]
}

function parseScalar(frontmatter: string, key: string): string | undefined {
  const match = frontmatter.match(new RegExp("^" + key + ":\\s*(.*)$", "m"))
  if (!match) return undefined
  return match[1].trim().replace(/^["']|["']$/g, "")
}

function parseArray(frontmatter: string, key: string): string[] {
  const match = frontmatter.match(new RegExp("^" + key + ":\\s*\\[(.*)\\]", "m"))
  if (!match) return []
  return match[1].split(",").map((item) => item.trim().replace(/^["']|["']$/g, "")).filter(Boolean)
}

function discoverSkillFiles(directory: string, found: Map<string, string[]>) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const child = path.join(directory, entry.name)
    const skillFile = path.join(child, "SKILL.md")
    if (existsSync(skillFile)) {
      const paths = found.get(entry.name) ?? []
      paths.push(skillFile)
      found.set(entry.name, paths)
    }
    discoverSkillFiles(child, found)
  }
}

async function main() {
  if (!existsSync(indexPath)) throw new Error("Curated registry index.json is missing")
  const current = JSON.parse(await Bun.file(indexPath).text()) as { version?: string; skills?: Array<{ name: string }> }
  if (!Array.isArray(current.skills) || current.skills.length === 0) {
    throw new Error("index.json must contain a non-empty curated skills allowlist")
  }

  const discovered = new Map<string, string[]>()
  discoverSkillFiles(skillDir, discovered)
  const entries: RegistryEntry[] = []

  for (const item of current.skills) {
    const matches = discovered.get(item.name) ?? []
    if (matches.length !== 1) {
      throw new Error(`Expected exactly one SKILL.md for registry entry "${item.name}", found ${matches.length}`)
    }
    const skillPath = matches[0]
    const content = await Bun.file(skillPath).text()
    const fmMatch = content.match(/^---\n([\s\S]*?)\n---/)
    if (!fmMatch) throw new Error(`Missing YAML frontmatter: ${skillPath}`)
    const fm = fmMatch[1]

    const dir = path.dirname(skillPath)
    const files: string[] = []
    const walk = (directory: string, prefix: string) => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name
        if (entry.isDirectory()) walk(path.join(directory, entry.name), relative)
        else files.push(relative)
      }
    }
    walk(dir, "")
    files.sort()

    const sha256 = parseScalar(fm, "sha256")
    const signature = parseScalar(fm, "signature")
    const signedBy = parseScalar(fm, "signed_by")
    const verified = await SkillSigning.verify({ content, sha256, signature, signed_by: signedBy })
    if (verified === "tampered") {
      throw new Error(`Refusing to refresh registry with a tampered or invalidly signed skill: ${skillPath}`)
    }

    const entry: RegistryEntry = {
      name: item.name,
      description: parseScalar(fm, "description") ?? "",
      verified,
      tags: parseArray(fm, "tags"),
      tech_stack: parseArray(fm, "tech_stack"),
      cwe_ids: parseArray(fm, "cwe_ids"),
      files,
    }
    const category = parseScalar(fm, "category")
    const owaspId = parseScalar(fm, "owasp_id")
    if (category) entry.category = category
    if (owaspId) entry.owasp_id = owaspId
    entries.push(entry)
  }

  const index = { version: current.version ?? "1.0", skills: entries }
  await Bun.write(indexPath, JSON.stringify(index, null, 2) + "\n")
  console.log(`Refreshed curated registry at ${indexPath}`)
  console.log(`  ${entries.length} allowlisted skills indexed`)
  console.log(`  ${entries.filter((entry) => entry.verified === "official").length} official; ${entries.filter((entry) => entry.verified === "community").length} community; ${entries.filter((entry) => entry.verified === "unverified").length} unverified`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
