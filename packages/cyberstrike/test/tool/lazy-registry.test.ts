import { afterEach, describe, expect, test } from "bun:test"
import { LazyToolRegistry } from "../../src/tool/lazy-registry"

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
    expect(LazyToolRegistry.getAll().map((tool) => tool.id)).toContain("test_server_search_old")

    LazyToolRegistry.reconcileServerTools("test.server", [
      { name: "keep_tool", description: "updated capability description" },
      { name: "new_tool", description: "new capability description" },
    ])

    const tools = LazyToolRegistry.getAll().filter((tool) => tool.mcpServer === "test.server")
    expect(tools.map((tool) => tool.id).sort()).toEqual(["test_server_keep_tool", "test_server_new_tool"])
    expect(tools.find((tool) => tool.id === "test_server_keep_tool")?.summary).toBe("updated capability description")
    expect(LazyToolRegistry.search("updated capability")).toContainEqual(
      expect.objectContaining({ id: "test_server_keep_tool" }),
    )
  })

  test("does not return every tool for empty queries or invalid limits", () => {
    LazyToolRegistry.reconcileServerTools("test.server", [
      { name: "search_users", description: "search user directory" },
      { name: "delete_user", description: "delete a user" },
    ])
    expect(LazyToolRegistry.search("   ")).toEqual([])
    expect(LazyToolRegistry.search("search", 0)).toEqual([])
    expect(LazyToolRegistry.search("search", -1)).toEqual([])
    expect(LazyToolRegistry.search("search").map((tool) => tool.id)).toContain("test_server_search_users")
  })
})
