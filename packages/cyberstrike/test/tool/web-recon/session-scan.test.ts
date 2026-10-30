import { expect, test } from "bun:test"

test("path-scoped session scans keep endpoint checks while excluding origin-root probes", () => {
  const capturedApiURLs = ["https://api.example.test/api/profile", "https://api.example.test/api/orders"]
  const rootAuthorizedOrigins = new Set(["https://root.example.test"])
  const corsTargets = [
    ...capturedApiURLs,
    ...(rootAuthorizedOrigins.has("https://root.example.test") ? ["https://root.example.test/"] : []),
  ]
  const methodRoots = [...rootAuthorizedOrigins].map((origin) => origin + "/")

  expect(corsTargets).toEqual([
    "https://api.example.test/api/profile",
    "https://api.example.test/api/orders",
    "https://root.example.test/",
  ])
  expect(methodRoots).toEqual(["https://root.example.test/"])
  expect(corsTargets).not.toContain("https://api.example.test/")
  expect(methodRoots).not.toContain("https://api.example.test/")
})
