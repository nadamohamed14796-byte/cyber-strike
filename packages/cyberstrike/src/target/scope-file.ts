import path from "node:path"

/** Parse a plain-text scope list without inferring authorization or broadening entries. */
export function parseScopeFileContents(contents: string): string[] {
  const entries: string[] = []
  for (const [index, rawLine] of contents.replace(/^\uFEFF/, "").split(/\r?\n/).entries()) {
    const value = rawLine.trim()
    if (!value || value.startsWith("#") || value.startsWith("//")) continue
    if (value.length > 1000) {
      throw new Error("Scope file entry at line " + (index + 1) + " exceeds the 1000-character entry limit.")
    }
    // Preserve unfamiliar typed/structured entries as raw evidence. The scope
    // matcher only authorizes syntaxes it can interpret; opaque entries fail closed.
    entries.push(value)
  }
  if (entries.length === 0) throw new Error("Scope file contains no usable entries.")
  return entries
}

/** Resolve Windows Explorer paths to their Linux-side WSL path when running inside WSL/Linux. */
export function resolveScopeFilePath(input: string, cwd = process.cwd(), platform = process.platform): string {
  const value = input.trim()
  if (!value) throw new Error("Scope file path is required.")
  if (platform === "linux") {
    const wslPath = value.match(/^\\\\wsl(?:\.localhost|\$)?\\[^\\]+\\(.+)$/i)
    if (wslPath) return path.resolve("/" + wslPath[1].replace(/\\/g, "/"))
  }
  return path.resolve(cwd, value)
}
