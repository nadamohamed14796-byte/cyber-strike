import { describe, expect, test } from "bun:test"
import { requestsTargetWorkflow, targetWorkflowText, type TargetWorkflowMessage } from "../../src/session/target-workflow"

function message(role: string, text: string, options: { ignored?: boolean; synthetic?: boolean } = {}): TargetWorkflowMessage {
  return { info: { role }, parts: [{ type: "text", text, ...options }] }
}

describe("shared target workflow context", () => {
  test("inherits the root user's target intent when a child task omits it", () => {
    const root = [message("user", "Run recon against the approved target")]
    const child = [message("user", "Analyze the captured API response")]
    const combined = targetWorkflowText(root, child)

    expect(combined).toContain("Run recon")
    expect(combined).toContain("Analyze")
    expect(requestsTargetWorkflow(combined)).toBe(true)
  })

  test("recognizes Arabic target instructions", () => {
    expect(requestsTargetWorkflow("ابدأ استطلاع النطاق واجمع السب دومينات")).toBe(true)
  })

  test("ignores assistant, ignored, and synthetic messages", () => {
    const root = [
      message("assistant", "recon target report"),
      message("user", "ordinary note", { ignored: true }),
      message("user", "bug bounty", { synthetic: true }),
    ]
    expect(targetWorkflowText(root, [])).toBe("")
    expect(requestsTargetWorkflow(targetWorkflowText(root, []))).toBe(false)
  })

  test("does not enable target workflow for unrelated programming requests", () => {
    expect(requestsTargetWorkflow("Refactor the settings dialog and update unit tests")).toBe(false)
  })
})
