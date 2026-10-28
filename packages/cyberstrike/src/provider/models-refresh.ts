const SKIP_REFRESH_ARGUMENTS = new Set(["--get-yargs-completions", "--version", "-v", "--help", "-h"])

export function shouldRefreshModels(args: readonly string[], disabled: boolean): boolean {
  if (disabled) return false
  return !args.some((arg) => SKIP_REFRESH_ARGUMENTS.has(arg))
}
