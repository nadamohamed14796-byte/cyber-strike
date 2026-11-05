export function watcherBindingCandidates(platform: string, arch: string, libcHint?: string): string[] {
  const base = `@parcel/watcher-${platform}-${arch}`
  if (platform !== "linux") return [base]

  const preferred = libcHint === "musl" ? "musl" : "glibc"
  const fallback = preferred === "glibc" ? "musl" : "glibc"
  return [`${base}-${preferred}`, `${base}-${fallback}`]
}
