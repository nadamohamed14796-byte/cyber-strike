import path from "node:path"

const HACKERONE_ASSET_TYPES: Record<string, string> = {
  applestoreappid: "iOS: App Store",
  downloadableexecutables: "Executable",
  otherapk: "Android: .apk",
  otheripa: "iOS: .ipa",
  testflight: "iOS: Testflight",
  windowsappstoreappid: "Windows: Microsoft Store",
  aimodel: "AI Model",
  androidapk: "Android: .apk",
  androidplaystore: "Android Play Store",
  api: "API",
  awsaccount: "AWS Account",
  awscloudconfig: "AWS Cloud Config",
  azureaccount: "Azure Account",
  azurecloudconfig: "Azure Cloud Config",
  cidr: "CIDR",
  domain: "Domain",
  executable: "Executable",
  hardware: "Hardware",
  hardwareiot: "Hardware",
  googleplayappid: "Google Play App ID",
  iosappstore: "iOS: App Store",
  iosipa: "iOS: .ipa",
  iostestflight: "iOS: Testflight",
  ipaddress: "IP Address",
  other: "Other Asset",
  otherasset: "Other Asset",
  smartcontract: "Smart Contract",
  sourcecode: "Source Code",
  url: "URL",
  wildcard: "Wildcard",
  windowsmicrosoftstore: "Windows: Microsoft Store",
}

/** Parse plain-text lists and HackerOne tabular exports, separating explicit out-of-scope rows. */
export function parseScopeFileContentsDetailed(contents: string): { include: string[]; exclude: string[] } {
  let source = contents.replace(/^\uFEFF/, "").trim()
  // Accept a pasted JSON list as naturally as a plain text list.
  try {
    const parsed: unknown = JSON.parse(source)
    if (Array.isArray(parsed) && parsed.every((item) => typeof item === "string")) {
      source = parsed.join("\n")
    } else if (
      Array.isArray(parsed) &&
      parsed.length > 0 &&
      parsed.every((item) => item !== null && typeof item === "object" && !Array.isArray(item)) &&
      parsed.some((item) => item !== null && typeof item === "object" && "identifier" in item && "asset_type" in item)
    ) {
      const headers = [...new Set(parsed.flatMap((item) => Object.keys(item as Record<string, unknown>)))]
      const csvCell = (value: unknown) => {
        const text = value === null || value === undefined ? "" : typeof value === "object" ? JSON.stringify(value) : String(value)
        return '"' + text.replace(/"/g, '""') + '"'
      }
      source = [headers.map(csvCell).join(","), ...parsed.map((item) => headers.map((header) => csvCell((item as Record<string, unknown>)[header])).join(","))].join("\n")
    }
  } catch {
    // Plain text, CSV/TSV, and Markdown inputs are handled below.
  }

  const lines = source.split(/\r?\n/)
  const nonEmpty = lines.map((rawLine, index) => {
    let line = rawLine.trim()
    // Markdown code-fence-only lines are presentation, not scope data.
    if (line.startsWith(String.fromCharCode(96).repeat(3))) line = ""
    line = line.replace(/^(?:[-*+]\s+|\d+[.)]\s+)/, "")
    const markdownLink = line.match(/^\[[^\]]*\]\((https?:\/\/[^)]+)\)$/i)
    if (markdownLink) line = markdownLink[1]!
    return { line, index }
  }).filter((row) => row.line && !row.line.startsWith("#") && !row.line.startsWith("//") && !/^\|?\s*:?-{3,}(?:\s*\|\s*:?-{3,})*\s*\|?$/.test(row.line))
  if (nonEmpty.length === 0) throw new Error("Scope file contains no usable entries.")

  // HackerOne exports may be CSV/TSV; Markdown tables are also accepted when pasted directly.
  const firstLine = nonEmpty[0].line
  const delimiter = firstLine.includes("\t") ? "\t" : firstLine.includes("|") ? "|" : firstLine.includes(";") ? ";" : ","
  const parseRow = (line: string): string[] => {
    const fields: string[] = []
    let field = ""
    let quoted = false
    const rowText = delimiter === "|" ? line.replace(/^\s*\|/, "").replace(/\|\s*$/, "") : line
    for (let index = 0; index < rowText.length; index++) {
      const char = rowText[index]!
      if (char === '"') {
        if (quoted && rowText[index + 1] === '"') { field += '"'; index++ }
        else quoted = !quoted
      } else if (char === delimiter && !quoted) {
        fields.push(field.trim())
        field = ""
      } else field += char
    }
    fields.push(field.trim())
    return fields
  }
  const normalizeTypeKey = (part: string) => part.toLowerCase().replace(/[^a-z0-9]+/g, "")
  const header = parseRow(nonEmpty[0].line).map(normalizeTypeKey)
  const identifierColumn = header.indexOf("identifier")
  const typeColumn = header.indexOf("assettype")
  // Submission/bounty eligibility is not a scope decision. Only explicit scope columns may exclude assets.
  const scopeColumn = header.findIndex((name) => ["inscope", "isinscope", "scope"].includes(name))
  if (identifierColumn >= 0 && typeColumn >= 0) {
    const entries: string[] = []
    const excludedEntries: string[] = []
    for (const row of nonEmpty.slice(1)) {
      if (row.line.length > 1000) throw new Error("Scope file entry at line " + (row.index + 1) + " exceeds the 1000-character entry limit.")
      const columns = parseRow(row.line)
      const identifier = columns[identifierColumn]?.trim()
      const rawType = columns[typeColumn]?.trim()
      if (!identifier || !rawType) continue
      const key = normalizeTypeKey(rawType)
      const type = HACKERONE_ASSET_TYPES[key] ?? rawType
      const entry = type + ": " + identifier
      if (scopeColumn >= 0) {
        const rawScope = columns[scopeColumn]?.trim().toLowerCase().replace(/[_-]+/g, " ")
        if (["true", "1", "yes", "in scope", "inscope", "included"].includes(rawScope ?? "")) entries.push(entry)
        else if (["false", "0", "no", "out of scope", "outofscope", "excluded"].includes(rawScope ?? "")) excludedEntries.push(entry)
        else {
          throw new Error(
            "Scope row at line " + (row.index + 1) +
            " has an empty or unrecognized explicit scope value; refusing to guess whether the asset is in scope."
          )
        }
      } else {
        // Fields such as eligible_for_submission and eligible_for_bounty describe reporting/reward eligibility,
        // not authorization to test the asset.
        entries.push(entry)
      }
    }
    if (entries.length + excludedEntries.length === 0) throw new Error("HackerOne scope export contains no usable asset rows.")
    if (entries.length === 0) throw new Error("HackerOne scope export has no rows with eligible_for_submission=true; refusing to configure an empty in-scope manifest.")
    return { include: entries, exclude: excludedEntries }
  }

  const entries: string[] = []
  for (const row of nonEmpty) {
    if (row.line.length > 1000) throw new Error("Scope file entry at line " + (row.index + 1) + " exceeds the 1000-character entry limit.")
    entries.push(row.line)
  }
  return { include: entries, exclude: [] }
}

/**
 * Compatibility wrapper for callers that expect an include-only list. If a
 * HackerOne export contains explicit out-of-scope rows, require the caller to
 * use the detailed parser so exclusions can never be silently discarded.
 */
export function parseScopeFileContents(contents: string): string[] {
  const parsed = parseScopeFileContentsDetailed(contents)
  if (parsed.exclude.length) {
    throw new Error("Scope file contains explicitly out-of-scope rows; use parseScopeFileContentsDetailed so exclusions are preserved.")
  }
  return parsed.include
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
