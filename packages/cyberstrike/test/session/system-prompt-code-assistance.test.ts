import { describe, expect, test } from "bun:test"
import { SystemPrompt } from "../../src/session/system"
import type { Provider } from "../../src/provider/provider"

describe("system prompt code assistance", () => {
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
