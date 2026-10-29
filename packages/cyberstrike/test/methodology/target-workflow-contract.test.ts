import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const contract = readFileSync(
  new URL("../../src/agent/prompt/methodology/target-workflow.txt", import.meta.url),
  "utf-8",
)

test("target workflow defines the full resumable lifecycle without arbitrary finding-count caps", () => {
  expect(contract).toContain("End-to-end engagement lifecycle")
  expect(contract).toContain("reuse the current session")
  expect(contract).toContain("Do not impose arbitrary source/host/URL/result/time caps")
  expect(contract).toContain("Keep going while a concrete, in-scope step is likely to add or validate a finding")
  expect(contract).not.toContain("five distinct, validated, reportable findings")
  expect(contract).toContain("INFO/LOW intel, scanner alerts, chain hypotheses")
  expect(contract).toContain("Generate and verify the final report")
  expect(contract).toContain("Preserve the session and workspace")
})

test("missing tools are installed by exact name and are not silently substituted", () => {
  expect(contract).toContain("call `ensure_tools` with that exact tool name")
  expect(contract).toContain("Do not spend time hunting for a substitute")
  expect(contract).toContain("mark that method blocked")
})


test("primary workflow steps have unique numbering and closeout comes after investigation", () => {
  const primarySteps = [...contract.matchAll(/^\s*(\d+)\.\s/gm)].map((match) => match[1])
  expect(new Set(primarySteps).size).toBe(primarySteps.length)
  expect(contract.indexOf("6. **Chain skills and delegate only from evidence.")).toBeGreaterThan(
    contract.indexOf("5. **Goal and stop condition:"),
  )
  expect(contract.indexOf("9. **Verify, report, and close cleanly.")).toBeGreaterThan(
    contract.indexOf("8a. **Reconcile coverage before finishing."),
  )
})
