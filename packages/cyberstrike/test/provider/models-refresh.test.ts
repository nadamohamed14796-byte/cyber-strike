import { describe, expect, test } from "bun:test"
import { selectLocalModelsCatalog, shouldRefreshModels } from "../../src/provider/models-refresh"

describe("shouldRefreshModels", () => {
  test("refreshes during normal application startup", () => {
    expect(shouldRefreshModels(["cyberstrike"], false)).toBe(true)
    expect(shouldRefreshModels(["cyberstrike", "recon"], false)).toBe(true)
  })

  test("respects explicit models fetch disablement", () => {
    expect(shouldRefreshModels(["cyberstrike"], true)).toBe(false)
    expect(shouldRefreshModels(["cyberstrike", "--version"], true)).toBe(false)
  })

  test("does not make network calls for version, help, or completion queries", () => {
    for (const flag of ["--version", "-v", "--help", "-h", "--get-yargs-completions"]) {
      expect(shouldRefreshModels(["cyberstrike", flag], false)).toBe(false)
    }
  })

  test("does not refresh when a fast-exit flag appears alongside other arguments", () => {
    expect(shouldRefreshModels(["cyberstrike", "--version", "--verbose"], false)).toBe(false)
    expect(shouldRefreshModels(["cyberstrike", "--help", "recon"], false)).toBe(false)
  })
})

describe("selectLocalModelsCatalog", () => {
  test("prefers a valid on-disk cache, including an empty cache", () => {
    const cache = { cached: true }
    expect(selectLocalModelsCatalog(cache, { snapshot: true })).toBe(cache)
    expect(selectLocalModelsCatalog({}, { snapshot: true })).toEqual({})
  })

  test("falls back to a valid bundled snapshot when the cache is missing or invalid", () => {
    const snapshot = { bundled: true }
    expect(selectLocalModelsCatalog(undefined, snapshot)).toBe(snapshot)
    expect(selectLocalModelsCatalog("invalid", snapshot)).toBe(snapshot)
  })

  test("returns an empty catalogue when no local source is usable", () => {
    expect(selectLocalModelsCatalog(undefined, undefined)).toEqual({})
    expect(selectLocalModelsCatalog([], null)).toEqual({})
  })
})
