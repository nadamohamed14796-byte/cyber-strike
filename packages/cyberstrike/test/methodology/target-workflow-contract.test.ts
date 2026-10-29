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
  expect(contract).toContain("The first loop-detector warning must schedule a recovery turn with tools available")
  expect(contract).toContain("Only continued repetition after that recovery may force a terminal wrap-up")
  expect(contract).toContain("Do not ask the user to resume routine work")
})

test("missing tools use the maintained-tool catalog and are not silently downgraded", () => {
  expect(contract).toContain("community-tool-selection")
  expect(contract).toContain("returned `<skill_files>`")
  expect(contract).toContain("Call `ensure_tools` for the selected tool")
  expect(contract).toContain("do not install or execute a legacy command")
  expect(contract).toContain("continue independent work")
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
