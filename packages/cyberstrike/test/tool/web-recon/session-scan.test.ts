import { expect, test } from "bun:test"
import { sessionScanProbeTargets } from "../../../src/tool/web-recon/session-scan"

test("path-scoped session scans keep endpoint checks while excluding origin-root probes", () => {
  const origins = new Map([
    ["https://api.example.test", {
      apis: new Set(["https://api.example.test/api/profile", "https://api.example.test/api/orders"]),
      pages: new Set(["https://api.example.test/portal"]),
    }],
    ["https://root.example.test", {
      apis: new Set<string>(),
      pages: new Set(["https://root.example.test/"]),
    }],
  ])

  const targets = sessionScanProbeTargets(origins, new Set(["https://root.example.test"]))

  expect(targets.corsTargets).toEqual([
    "https://api.example.test/api/profile",
    "https://api.example.test/api/orders",
    "https://root.example.test/",
  ])
  expect(targets.methodRoots).toEqual(["https://root.example.test/"])
  expect(targets.corsTargets).not.toContain("https://api.example.test/")
  expect(targets.methodRoots).not.toContain("https://api.example.test/")
})
