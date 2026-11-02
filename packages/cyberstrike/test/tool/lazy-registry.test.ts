import { describe, expect, spyOn, test } from "bun:test"
import { LazyToolRegistry } from "../../src/tool/lazy-registry"
import { MCP } from "../../src/mcp"
import { Bus } from "../../src/bus"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

async function withProject<T>(fn: (directory: string) => Promise<T> | T): Promise<T> {
  await using tmp = await tmpdir()
  try {
    return await Instance.provide({ directory: tmp.path, fn: () => fn(tmp.path) })
  } finally {
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        await Instance.dispose()
      },
    })
  }
}

describe("lazy tool registry snapshot reconciliation", () => {
  test("updates changed metadata and removes tools missing from a successful snapshot", async () => {
    await withProject(() => {
      LazyToolRegistry.reconcileServerTools("test.server", [
        { name: "search_old", description: "old capability description" },
        { name: "keep_tool", description: "kept capability" },
      ])
      expect(LazyToolRegistry.getAll().find((tool) => tool.mcpServer === "test.server" && tool.name === "search_old")?.id)
        .toContain("search_old")

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
  })

  test("invalidates a loaded tool when only its input schema changes", async () => {
    await withProject(async () => {
      const name = "schema_sensitive_tool"
      const id = MCP.toolID("test.server", name)
      const firstSchema = { type: "object", properties: { query: { type: "string" } } }
      const updatedSchema = { type: "object", properties: { query: { type: "string" } }, required: ["query"] }

      LazyToolRegistry.reconcileServerTools("test.server", [
        { name, description: "same description", inputSchema: firstSchema },
      ])
      const toolsSpy = spyOn(MCP, "tools").mockResolvedValue({
        [id]: { description: "same description", inputSchema: firstSchema, execute: async () => ({ content: [] }) },
      } as any)
      try {
        await LazyToolRegistry.load([id])
        expect(LazyToolRegistry.isLoaded(id)).toBe(true)
        LazyToolRegistry.reconcileServerTools("test.server", [
          { name, description: "same description", inputSchema: updatedSchema },
        ])
        expect(LazyToolRegistry.isLoaded(id)).toBe(false)
        expect(LazyToolRegistry.getLoaded().some((tool) => tool.id === id)).toBe(false)
      } finally {
        toolsSpy.mockRestore()
      }
    })
  })

  test("preserves a loaded tool when its schema is structurally unchanged", async () => {
    await withProject(async () => {
      const name = "stable_schema_tool"
      const id = MCP.toolID("test.server", name)
      const schema = { type: "object", properties: { limit: { type: "integer" }, query: { type: "string" } } }
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
        LazyToolRegistry.reconcileServerTools("test.server", [
          {
            name,
            description: "same description",
            inputSchema: { properties: { query: { type: "string" }, limit: { type: "integer" } }, type: "object" },
          },
        ])
        expect(LazyToolRegistry.isLoaded(id)).toBe(true)
        expect(LazyToolRegistry.getLoaded().find((tool) => tool.id === id)).toBe(before)
      } finally {
        toolsSpy.mockRestore()
      }
    })
  })

  test("disambiguates normalized tool names and server/tool boundaries", async () => {
    await withProject(() => {
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

      expect(MCP.toolID("test.server", "foo.bar")).not.toBe(MCP.toolID("test.server", "foo_bar"))
      expect(MCP.toolID("a_b", "c")).not.toBe(MCP.toolID("a", "b_c"))
      LazyToolRegistry.reconcileServerTools("a_b", [{ name: "c", description: "first" }])
      LazyToolRegistry.reconcileServerTools("a", [{ name: "b_c", description: "second" }])
      expect(LazyToolRegistry.getAll().filter((tool) => tool.mcpServer === "a_b" || tool.mcpServer === "a")).toHaveLength(2)
    })
  })

  test("does not return every tool for empty queries or invalid limits", async () => {
    await withProject(() => {
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

  test("scopes same-named MCP servers to independent projects", async () => {
    await using first = await tmpdir()
    await using second = await tmpdir()
    try {
      await Instance.provide({
        directory: first.path,
        fn: () => LazyToolRegistry.reconcileServerTools("same.server", [
          { name: "lookup", description: "project alpha tool" },
        ]),
      })
      await Instance.provide({
        directory: second.path,
        fn: () => LazyToolRegistry.reconcileServerTools("same.server", [
          { name: "lookup", description: "project beta tool" },
        ]),
      })
      await Instance.provide({
        directory: first.path,
        fn: () => {
          expect(LazyToolRegistry.search("alpha")).toHaveLength(1)
          expect(LazyToolRegistry.search("beta")).toHaveLength(0)
        },
      })
      await Instance.provide({
        directory: second.path,
        fn: () => {
          expect(LazyToolRegistry.search("beta")).toHaveLength(1)
          expect(LazyToolRegistry.search("alpha")).toHaveLength(0)
        },
      })
    } finally {
      await Instance.provide({ directory: first.path, fn: () => Instance.dispose() })
      await Instance.provide({ directory: second.path, fn: () => Instance.dispose() })
    }
  })

  test("reuses a connection snapshot between turns and refreshes on ToolsChanged", async () => {
    await withProject(async () => {
      let listCount = 0
      let currentDefinitions = [{ name: "search_users", description: "search user directory" }]
      const client = {
        listTools: async () => {
          listCount++
          return { tools: currentDefinitions }
        },
      }
      const statusSpy = spyOn(MCP, "status").mockResolvedValue({ "test.server": { status: "connected" } } as any)
      const boltStatusSpy = spyOn(MCP, "boltStatus").mockResolvedValue({} as any)
      const clientsSpy = spyOn(MCP, "clients").mockResolvedValue({ "test.server": client } as any)
      try {
        await LazyToolRegistry.init()
        await LazyToolRegistry.init()
        expect(listCount).toBe(1)

        currentDefinitions = [{ name: "lookup_orders", description: "look up orders" }]
        await Bus.publish(MCP.ToolsChanged, { server: "test.server" })
        expect(listCount).toBe(2)
        expect(LazyToolRegistry.search("lookup orders").map((tool) => tool.name)).toEqual(["lookup_orders"])
      } finally {
        clientsSpy.mockRestore()
        boltStatusSpy.mockRestore()
        statusSpy.mockRestore()
      }
    })
  })

  test("lists independent MCP servers concurrently", async () => {
    await withProject(async () => {
      const started: string[] = []
      const pending: Array<() => void> = []
      const makeClient = (name: string) => ({
        listTools: async () => {
          started.push(name)
          await new Promise<void>((resolve) => pending.push(resolve))
          return { tools: [{ name: "lookup", description: name }] }
        },
      })
      const statusSpy = spyOn(MCP, "status").mockResolvedValue({
        alpha: { status: "connected" },
        beta: { status: "connected" },
      } as any)
      const boltStatusSpy = spyOn(MCP, "boltStatus").mockResolvedValue({} as any)
      const clientsSpy = spyOn(MCP, "clients").mockResolvedValue({
        alpha: makeClient("alpha"),
        beta: makeClient("beta"),
      } as any)
      try {
        const init = LazyToolRegistry.init()
        await new Promise((resolve) => setTimeout(resolve, 0))
        expect(started.sort()).toEqual(["alpha", "beta"])
        pending.forEach((resolve) => resolve())
        await init
      } finally {
        clientsSpy.mockRestore()
        boltStatusSpy.mockRestore()
        statusSpy.mockRestore()
      }
    })
  })

  test("avoids re-listing MCP tools when requested tools are already loaded", async () => {
    await withProject(async () => {
      const id = MCP.toolID("test.server", "already_loaded")
      LazyToolRegistry.reconcileServerTools("test.server", [{ name: "already_loaded", description: "ready" }])
      const toolsSpy = spyOn(MCP, "tools").mockResolvedValue({
        [id]: { description: "ready", inputSchema: { type: "object" }, execute: async () => ({ content: [] }) },
      } as any)
      try {
        await LazyToolRegistry.load([id])
        await LazyToolRegistry.load([id])
        expect(toolsSpy).toHaveBeenCalledTimes(1)
      } finally {
        toolsSpy.mockRestore()
      }
    })
  })
})
