import { afterEach, describe, expect, test } from "bun:test"
import { LazyToolRegistry } from "../../src/tool/lazy-registry"
import { MCP } from "../../src/mcp"

describe("lazy tool registry snapshot reconciliation", () => {
  afterEach(() => {
    for (const tool of LazyToolRegistry.getAll()) {
      if (tool.mcpServer === "test.server") LazyToolRegistry.unload([tool.id])
    }
    LazyToolRegistry.reconcileServerTools("test.server", [])
  })

  test("updates changed metadata and removes tools missing from a successful snapshot", () => {
    LazyToolRegistry.reconcileServerTools("test.server", [
      { name: "search_old", description: "old capability description" },
      { name: "keep_tool", description: "kept capability" },
    ])
    expect(LazyToolRegistry.getAll().find((tool) => tool.mcpServer === "test.server" && tool.name === "search_old")?.id).toContain("search_old")

    LazyToolRegistry.reconcileServerTools("test.server", [
      { name: "keep_tool", description: "updated capability description" },
      { name: "new_tool", description: "new capability description" },
    ])

    const tools = LazyToolRegistry.getAll().filter((tool) => tool.mcpServer === "test.server")
    expect(tools.map((tool) => tool.name).sort()).toEqual(["keep_tool", "new_tool"])
    expect(tools.find((tool) => tool.name === "keep_tool")?.summary).toBe("updated capability description")
    expect(LazyToolRegistry.search("updated capability")).toContainEqual(
      expect.objectContaining({ mcpServer: "test.server", name: "keep_tool" }),
    )
  })

  test("disambiguates tool names that normalize to the same readable ID", () => {
    LazyToolRegistry.reconcileServerTools("test.server", [
      { name: "foo.bar", description: "dotted tool" },
      { name: "foo_bar", description: "underscored tool" },
    ])
    const tools = LazyToolRegistry.getAll().filter((tool) => tool.mcpServer === "test.server")
    const dotted = tools.find((tool) => tool.name === "foo.bar")
    const underscored = tools.find((tool) => tool.name === "foo_bar")
    expect(dotted).toBeTruthy()
    expect(underscored).toBeTruthy()
    expect(dotted?.id).not.toBe(underscored?.id)
    expect(LazyToolRegistry.search("dotted tool")).toContainEqual(expect.objectContaining({ name: "foo.bar" }))
    expect(LazyToolRegistry.search("underscored tool")).toContainEqual(expect.objectContaining({ name: "foo_bar" }))
  })

  test("canonical IDs distinguish both normalized names and server/tool boundaries", () => {
    expect(MCP.toolID("test.server", "foo.bar")).not.toBe(MCP.toolID("test.server", "foo_bar"))
    expect(MCP.toolID("a_b", "c")).not.toBe(MCP.toolID("a", "b_c"))

    LazyToolRegistry.reconcileServerTools("a_b", [{ name: "c", description: "first" }])
    LazyToolRegistry.reconcileServerTools("a", [{ name: "b_c", description: "second" }])
    const tools = LazyToolRegistry.getAll().filter((tool) => tool.mcpServer === "a_b" || tool.mcpServer === "a")
    expect(tools).toHaveLength(2)
    expect(new Set(tools.map((tool) => tool.id)).size).toBe(2)
    LazyToolRegistry.reconcileServerTools("a_b", [])
    LazyToolRegistry.reconcileServerTools("a", [])
  })

  test("does not return every tool for empty queries or invalid limits", () => {
    LazyToolRegistry.reconcileServerTools("test.server", [
      { name: "search_users", description: "search user directory" },
      { name: "delete_user", description: "delete a user" },
    ])
    expect(LazyToolRegistry.search("   ")).toEqual([])
    expect(LazyToolRegistry.search("search", 0)).toEqual([])
    expect(LazyToolRegistry.search("search", -1)).toEqual([])
    expect(LazyToolRegistry.search("search").map((tool) => tool.name)).toContain("search_users")
  })
})
