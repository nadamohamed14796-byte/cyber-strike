const SKIP_REFRESH_ARGUMENTS = new Set(["--get-yargs-completions", "--version", "-v", "--help", "-h"])

export function isModelsCatalog(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export function selectLocalModelsCatalog(cache: unknown, snapshot: unknown): Record<string, unknown> {
  if (isModelsCatalog(cache)) return cache
  if (isModelsCatalog(snapshot)) return snapshot
  return {}
}

export function shouldRefreshModels(args: readonly string[], disabled: boolean): boolean {
  if (disabled) return false
  return !args.some((arg) => SKIP_REFRESH_ARGUMENTS.has(arg))
}
