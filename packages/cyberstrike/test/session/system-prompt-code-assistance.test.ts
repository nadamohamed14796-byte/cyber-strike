import { describe, expect, test } from "bun:test"
import { SystemPrompt } from "../../src/session/system"
import type { Provider } from "../../src/provider/provider"

describe("system prompt code assistance", () => {
  test("is included in Codex instructions", () => {
    expect(SystemPrompt.instructions()).toContain("General-purpose programming and code-solving")
    expect(SystemPrompt.instructions()).toContain("any programming language")
  })

  test("is available as a reusable prompt for custom agents", () => {
    expect(SystemPrompt.codeAssistance()).toContain("complete corrected snippet")
  })

  const providers = [
    "gpt-5.2",
    "gpt-4.1",
    "gemini-2.5-pro",
    "claude-sonnet-4",
    "trinity-mini",
    "deepseek-ai/DeepSeek-V4-Flash-0731",
  ]

  for (const id of providers) {
    test(`includes general code assistance for ${id}`, () => {
      const prompts = SystemPrompt.provider({ api: { id } } as unknown as Provider.Model)

      expect(prompts).toHaveLength(2)
      expect(prompts[1]).toContain("General-purpose programming and code-solving")
      expect(prompts[1]).toContain("any programming language")
      expect(prompts[1]).toContain("CodeSearch is an optional external reference-retrieval aid")
    })
  }
})
