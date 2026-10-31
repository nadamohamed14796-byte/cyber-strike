import { afterEach, describe, expect, spyOn, test } from "bun:test"
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

  test("invalidates a loaded tool when only its input schema changes", async () => {
    const name = "schema_sensitive_tool"
    const id = MCP.toolID("test.server", name)
    const firstSchema = {
      type: "object",
      properties: { query: { type: "string" } },
    }
    const updatedSchema = {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    }

    LazyToolRegistry.reconcileServerTools("test.server", [
      { name, description: "same description", inputSchema: firstSchema },
    ])

    const mockedTool = {
      description: "same description",
      inputSchema: firstSchema,
      execute: async () => ({ content: [] }),
    }
    const toolsSpy = spyOn(MCP, "tools").mockResolvedValue({ [id]: mockedTool } as any)
    try {
      await LazyToolRegistry.load([id])
      expect(LazyToolRegistry.isLoaded(id)).toBe(true)

      // Name and description are unchanged; the new required input must still
      // invalidate the previously loaded executable definition.
      LazyToolRegistry.reconcileServerTools("test.server", [
        { name, description: "same description", inputSchema: updatedSchema },
      ])
      expect(LazyToolRegistry.isLoaded(id)).toBe(false)
      expect(LazyToolRegistry.getLoaded().some((tool) => tool.id === id)).toBe(false)
    } finally {
      toolsSpy.mockRestore()
      LazyToolRegistry.unload([id])
    }
  })

  test("preserves a loaded tool when its schema is structurally unchanged", async () => {
    const name = "stable_schema_tool"
    const id = MCP.toolID("test.server", name)
    const schema = {
      type: "object",
      properties: { limit: { type: "integer" }, query: { type: "string" } },
    }
    LazyToolRegistry.reconcileServerTools("test.server", [
      { name, description: "same description", inputSchema: schema },
    ])
    const toolsSpy = spyOn(MCP, "tools").mockResolvedValue({
      [id]: { description: "same description", inputSchema: schema, execute: async () => ({ content: [] }) },
    } as any)
    try {
      await LazyToolRegistry.load([id])
      const before = LazyToolRegistry.getLoaded().find((tool) => tool.id === id)
      expect(before).toBeDefined()

      // Object key order is irrelevant to the schema fingerprint.
      LazyToolRegistry.reconcileServerTools("test.server", [
        {
          name,
          description: "same description",
          inputSchema: {
            properties: { query: { type: "string" }, limit: { type: "integer" } },
            type: "object",
          },
        },
      ])
      expect(LazyToolRegistry.isLoaded(id)).toBe(true)
      expect(LazyToolRegistry.getLoaded().find((tool) => tool.id === id)).toBe(before)
    } finally {
      toolsSpy.mockRestore()
      LazyToolRegistry.unload([id])
    }
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
