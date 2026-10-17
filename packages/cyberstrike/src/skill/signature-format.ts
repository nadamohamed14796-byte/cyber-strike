/**
 * Canonical content hashing for skill signatures.
 *
 * Signature metadata belongs to the YAML frontmatter only. Removing similarly
 * named lines from the skill body would leave body content outside the integrity
 * check, allowing edits to lines such as "signature: ..." to go undetected.
 */
export function stripSkillSigningMetadata(content: string): string {
  const frontmatter = /^(---[ \t]*\r?\n)([\s\S]*?)(\r?\n---[ \t]*(?:\r?\n|$))/.exec(content)
  if (!frontmatter) return content.trim()

  const [matched, opening, metadata, closing] = frontmatter
  const cleanMetadata = metadata.replace(/^(?:sha256|signature|signed_by):[^\r\n]*(?:\r?\n|$)/gm, "")
  const start = frontmatter.index
  const end = start + matched.length
  return (content.slice(0, start) + opening + cleanMetadata + closing + content.slice(end)).trim()
}

export function hashSkillContent(content: string): string {
  const hasher = new Bun.CryptoHasher("sha256")
  hasher.update(stripSkillSigningMetadata(content))
  return hasher.digest("hex")
}
