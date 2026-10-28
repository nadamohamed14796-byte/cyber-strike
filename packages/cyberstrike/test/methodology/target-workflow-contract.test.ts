import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const contract = readFileSync(
  new URL("../../src/agent/prompt/methodology/target-workflow.txt", import.meta.url),
  "utf-8",
)

test("target workflow defines autonomous recon handoffs, one workspace, and evidence-based closeout", () => {
  expect(contract).toContain("Run end-to-end without making the user drive each phase")
  expect(contract).toContain("Do not ask the user to say")
  expect(contract).toContain("One authoritative scope decision")
  expect(contract).toContain("A leading wildcard such as *.example.com authorizes example.com and all subdomains")
  expect(contract).toContain("Exclusions always override inclusions")
  expect(contract).toContain("One canonical workspace and output set")
  expect(contract).toContain("`subdomains.txt`")
  expect(contract).toContain("`live-hosts.txt`")
  expect(contract).toContain("`urls.txt`")
  expect(contract).toContain("`parameters.txt`")
  expect(contract).toContain("`endpoints.txt`")
  expect(contract).toContain("reports/recon-final.md")
  expect(contract).toContain("Generate or update `reports/recon-final.md`")
  expect(contract).toContain("automatically synchronizes a compact ordered checklist in the todo UI")
  expect(contract).toContain("runs/tmp/<phase>/")
  expect(contract).toContain("within 55 minutes")
  expect(contract).toContain("Never delete captured JavaScript/source-map bodies")
  expect(contract).toContain("Use `handoff` after a meaningful alternative fails or progress has stalled")
  expect(contract).toContain("The state becomes **partial**")
  expect(contract).toContain("`pending`, `running`, `blocked`, and `failed` work must be finished or explicitly handed off")
})

test("a selected missing CLI must be installed and verified before choosing a fallback", () => {
  expect(contract).toContain("call ensure_tools for that exact CLI")
  expect(contract).toContain("Do not silently replace a selected tool")
  expect(contract).toContain("Only after the exact install is genuinely blocked or fails")
  expect(contract).toContain("documented version/help check")
})
