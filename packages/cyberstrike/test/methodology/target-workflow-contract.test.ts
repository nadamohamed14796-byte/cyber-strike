import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const contract = readFileSync(
  new URL("../../src/agent/prompt/methodology/target-workflow.txt", import.meta.url),
  "utf-8",
)

test("target workflow defines autonomous recon handoffs, one workspace, and evidence-based closeout", () => {
  expect(contract).toContain("Run end-to-end without making the user drive each phase")
  expect(contract).toContain("do not stop to ask the user to say")
  expect(contract).toContain("One authoritative scope decision")
  expect(contract).toContain("A leading wildcard such as *.example.com authorizes example.com and all subdomains")
  expect(contract).toContain("Exclusions always override inclusions")
  expect(contract).toContain("One canonical workspace and output set")
  expect(contract).toContain("subdomains.txt, live-hosts.txt, urls.txt, parameters.txt, endpoints.txt")
  expect(contract).toContain("reports/recon-final.md")
  expect(contract).toContain("Generate or update reports/recon-final.md")
  expect(contract).toContain("automatically synchronizes a compact ordered `[recon:phase_id]` checklist")
  expect(contract).toContain("runs/tmp/<phase>/")
  expect(contract).toContain("within 55 minutes")
  expect(contract).toContain("do not delete captured JavaScript/source-map bodies")
})

test("a selected missing CLI must be installed and verified before choosing a fallback", () => {
  expect(contract).toContain("call ensure_tools for that exact CLI")
  expect(contract).toContain("Do not silently replace a selected tool")
  expect(contract).toContain("Only after the exact install is genuinely blocked or fails")
  expect(contract).toContain("documented version/help check")
})
