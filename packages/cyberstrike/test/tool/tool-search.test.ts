import { expect, test } from "bun:test"
import { ToolSearchTool, LoadToolsTool } from "../../src/tool/tool-search"

test("tool search returns a useful candidate set by default and supports broader discovery", async () => {
  const tool = await ToolSearchTool.init()
  expect(tool.parameters.parse({ query: "current checkpoint evidence gap" }).limit).toBe(10)
  expect(tool.parameters.parse({ query: "current checkpoint evidence gap", limit: 25 }).limit).toBe(25)
  expect(tool.description).toContain("not a tool allowlist")
  expect(tool.description).toContain("synonyms")
})

test("tool loading requires relevant search results, not a fixed tool list", async () => {
  const tool = await LoadToolsTool.init()
  expect(tool.description).toContain("only the exact IDs")
  expect(tool.description).toContain("without imposing a fixed number of tools per checkpoint")
})
