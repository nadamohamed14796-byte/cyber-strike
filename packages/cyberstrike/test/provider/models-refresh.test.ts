import { describe, expect, test } from "bun:test"
import { shouldRefreshModels } from "../../src/provider/models-refresh"

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
