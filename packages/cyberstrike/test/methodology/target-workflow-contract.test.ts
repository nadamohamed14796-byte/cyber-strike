import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const contract = readFileSync(
  new URL("../../src/agent/prompt/methodology/target-workflow.txt", import.meta.url),
  "utf-8",
)

test("target workflow defines the full resumable lifecycle and a reportable-finding stop goal", () => {
  expect(contract).toContain("End-to-end engagement lifecycle")
  expect(contract).toContain("reuse the current session")
  expect(contract).toContain("five distinct, validated, reportable findings")
  expect(contract).toContain("INFO/LOW intel, scanner alerts, chain hypotheses")
  expect(contract).toContain("Generate and verify the final report")
  expect(contract).toContain("Preserve the session and workspace")
})

test("missing tools are installed by exact name and are not silently substituted", () => {
  expect(contract).toContain("call `ensure_tools` with that exact tool name")
  expect(contract).toContain("Do not spend time hunting for a substitute")
  expect(contract).toContain("mark that method blocked")
})
