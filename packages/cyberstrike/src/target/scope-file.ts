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

/** Parse plain-text lists and HackerOne tabular exports without broadening authorization. */
export function parseScopeFileContents(contents: string): string[] {
  const lines = contents.replace(/^\uFEFF/, "").split(/\r?\n/)
  const nonEmpty = lines.map((line, index) => ({ line: line.trim(), index }))
    .filter((row) => row.line && !row.line.startsWith("#") && !row.line.startsWith("//"))
  if (nonEmpty.length === 0) throw new Error("Scope file contains no usable entries.")

  // HackerOne asset exports are tab-separated and include identifier + asset_type.
  // Convert rows to typed expressions, retaining unsupported asset kinds as evidence.
  const delimiter = nonEmpty[0].line.includes("\t") ? "\t" : nonEmpty[0].line.includes(";") ? ";" : ","
  const parseRow = (line: string): string[] => {
    if (delimiter === "\t") return line.split("\t")
    const fields: string[] = []
    let field = ""
    let quoted = false
    for (let index = 0; index < line.length; index++) {
      const char = line[index]!
      if (char === '"') {
        if (quoted && line[index + 1] === '"') { field += '"'; index++ }
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
  if (identifierColumn >= 0 && typeColumn >= 0) {
    const entries: string[] = []
    for (const row of nonEmpty.slice(1)) {
      if (row.line.length > 1000) throw new Error("Scope file entry at line " + (row.index + 1) + " exceeds the 1000-character entry limit.")
      const columns = parseRow(row.line)
      const identifier = columns[identifierColumn]?.trim()
      const rawType = columns[typeColumn]?.trim()
      if (!identifier || !rawType) continue
      const key = normalizeTypeKey(rawType)
      const type = HACKERONE_ASSET_TYPES[key] ?? rawType
      entries.push(type + ": " + identifier)
    }
    if (entries.length === 0) throw new Error("HackerOne scope export contains no usable asset rows.")
    return entries
  }

  const entries: string[] = []
  for (const row of nonEmpty) {
    if (row.line.length > 1000) throw new Error("Scope file entry at line " + (row.index + 1) + " exceeds the 1000-character entry limit.")
    entries.push(row.line)
  }
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
