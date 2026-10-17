import path from "node:path"

const HACKERONE_ASSET_TYPES: Record<string, string> = {
  aimodel: "AI Model",
  androidapk: "Android: .apk",
  androidplaystore: "Android Play Store",
  api: "API",
  awscloudconfig: "AWS Cloud Config",
  azurecloudconfig: "Azure Cloud Config",
  cidr: "CIDR",
  domain: "Domain",
  executable: "Executable",
  hardware: "Hardware",
  iosappstore: "iOS: App Store",
  iosipa: "iOS: .ipa",
  iostestflight: "iOS: Testflight",
  ipaddress: "IP Address",
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
  const header = nonEmpty[0].line.split("\t").map((part) => part.trim().toLowerCase().replace(/[ _-]+/g, ""))
  const identifierColumn = header.indexOf("identifier")
  const typeColumn = header.indexOf("assettype")
  if (identifierColumn >= 0 && typeColumn >= 0) {
    const entries: string[] = []
    for (const row of nonEmpty.slice(1)) {
      if (row.line.length > 1000) throw new Error("Scope file entry at line " + (row.index + 1) + " exceeds the 1000-character entry limit.")
      const columns = row.line.split("\t")
      const identifier = columns[identifierColumn]?.trim()
      const rawType = columns[typeColumn]?.trim()
      if (!identifier || !rawType) continue
      const key = rawType.toLowerCase().replace(/[ _-]+/g, "")
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
