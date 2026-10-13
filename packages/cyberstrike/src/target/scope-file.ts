/** Parse a plain-text scope list without inferring authorization or broadening entries. */
export function parseScopeFileContents(contents: string): string[] {
  const entries: string[] = []
  for (const [index, rawLine] of contents.split(/\r?\n/).entries()) {
    const value = rawLine.trim()
    if (!value || value.startsWith("#") || value.startsWith("//")) continue
    if (/\s/.test(value)) {
      throw new Error("Invalid scope file entry at line " + (index + 1) + ": entries must be one domain, wildcard, or IPv4 CIDR per line.")
    }
    entries.push(value)
  }
  if (entries.length === 0) throw new Error("Scope file contains no usable entries.")
  return entries
}
