import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION from "./batch.txt"
import { PermissionNext } from "../permission/next"

const DISALLOWED = new Set(["batch"])
const FILTERED_FROM_SUGGESTIONS = new Set(["invalid", "patch", ...DISALLOWED])

/** Keep nested batch execution behind the same per-agent and per-user tool gates as direct calls. */
export function batchAllowedToolIDs(input: {
  toolIDs: string[]
  agentID: string
  agentMode: "subagent" | "primary" | "all"
  permission: PermissionNext.Ruleset
  userTools?: Record<string, boolean>
}): Set<string> {
  const disabled = PermissionNext.disabled(input.toolIDs, input.permission)
  const internalImpactHandoff =
    input.agentMode === "subagent" &&
    input.agentID !== "impact-hunter" &&
    input.userTools?.task !== false

  return new Set(
    input.toolIDs.filter(
      (id) =>
        input.userTools?.[id] !== false &&
        (!disabled.has(id) || (id === "task" && internalImpactHandoff)),
    ),
  )
}

export const BatchTool = Tool.define("batch", async () => {
  return {
    description: DESCRIPTION,
    parameters: z.object({
      tool_calls: z
        .array(
          z.object({
            tool: z.string().describe("The name of the tool to execute"),
            parameters: z.object({}).loose().describe("Parameters for the tool"),
          }),
        )
        .min(1, "Provide at least one tool call")
        .describe("Array of tool calls to execute in parallel"),
    }),
    formatValidationError(error) {
      const formattedErrors = error.issues
        .map((issue) => {
          const path = issue.path.length > 0 ? issue.path.join(".") : "root"
          return `  - ${path}: ${issue.message}`
        })
        .join("\n")

      return `Invalid parameters for tool 'batch':\n${formattedErrors}\n\nExpected payload format:\n  [{"tool": "tool_name", "parameters": {...}}, {...}]`
    },
    async execute(params, ctx) {
      const { Session } = await import("../session")
      const { Identifier } = await import("../id/id")

      const toolCalls = params.tool_calls.slice(0, 25)
      const discardedCalls = params.tool_calls.slice(25)

      const { ToolRegistry } = await import("./registry")
      const { Agent } = await import("../agent/agent")
      const { Plugin } = await import("../plugin")
      const agent = await Agent.get(ctx.agent)
      if (!agent) throw new Error(`Cannot execute batch: agent "${ctx.agent}" is not registered.`)

      const latestUser = ctx.messages.findLast((message) => message.info.role === "user")?.info
      const userTools = latestUser?.role === "user" ? latestUser.tools : undefined
      const model = ctx.extra?.model as { providerID?: string; api?: { id?: string } } | undefined
      const availableTools = await ToolRegistry.tools(
        { modelID: model?.api?.id ?? "", providerID: model?.providerID ?? "" },
        agent,
      )
      const enabledToolIDs = batchAllowedToolIDs({
        toolIDs: availableTools.map((tool) => tool.id),
        agentID: ctx.agent,
        agentMode: agent.mode,
        permission: agent.permission,
        userTools,
      })
      const toolMap = new Map(availableTools.filter((tool) => enabledToolIDs.has(tool.id)).map((t) => [t.id, t]))

      const executeCall = async (call: (typeof toolCalls)[0]) => {
        const callStartTime = Date.now()
        const partID = Identifier.ascending("part")

        try {
          if (DISALLOWED.has(call.tool)) {
            throw new Error(
              `Tool '${call.tool}' is not allowed in batch. Disallowed tools: ${Array.from(DISALLOWED).join(", ")}`,
            )
          }

          const tool = toolMap.get(call.tool)
          if (!tool) {
            const availableToolsList = Array.from(toolMap.keys()).filter((name) => !FILTERED_FROM_SUGGESTIONS.has(name))
            throw new Error(
              `Tool '${call.tool}' not in registry. External tools (MCP, environment) cannot be batched - call them directly. Available tools: ${availableToolsList.join(", ")}`,
            )
          }
          const validatedParams = tool.parameters.parse(call.parameters)

          await Session.updatePart({
            id: partID,
            messageID: ctx.messageID,
            sessionID: ctx.sessionID,
            type: "tool",
            tool: call.tool,
            callID: partID,
            state: {
              status: "running",
              input: call.parameters,
              time: {
                start: callStartTime,
              },
            },
          })

          const nestedContext: Tool.Context = {
            ...ctx,
            callID: partID,
            metadata: (value) => ctx.metadata(value, partID, validatedParams as Record<string, any>),
            ask: (request) => ctx.ask(request, partID),
          }
          await Plugin.trigger(
            "tool.execute.before",
            { tool: call.tool, sessionID: ctx.sessionID, callID: partID },
            { args: validatedParams },
          )
          const result = await tool.execute(validatedParams, nestedContext)
          await Plugin.trigger(
            "tool.execute.after",
            { tool: call.tool, sessionID: ctx.sessionID, callID: partID, args: validatedParams },
            result,
          )

          await Session.updatePart({
            id: partID,
            messageID: ctx.messageID,
            sessionID: ctx.sessionID,
            type: "tool",
            tool: call.tool,
            callID: partID,
            state: {
              status: "completed",
              input: call.parameters,
              output: result.output,
              title: result.title,
              metadata: result.metadata,
              attachments: result.attachments,
              time: {
                start: callStartTime,
                end: Date.now(),
              },
            },
          })

          return { success: true as const, tool: call.tool, result }
        } catch (error) {
          await Session.updatePart({
            id: partID,
            messageID: ctx.messageID,
            sessionID: ctx.sessionID,
            type: "tool",
            tool: call.tool,
            callID: partID,
            state: {
              status: "error",
              input: call.parameters,
              error: error instanceof Error ? error.message : String(error),
              time: {
                start: callStartTime,
                end: Date.now(),
              },
            },
          })

          return { success: false as const, tool: call.tool, error }
        }
      }

      const results = await Promise.all(toolCalls.map((call) => executeCall(call)))

      // Add discarded calls as errors
      const now = Date.now()
      for (const call of discardedCalls) {
        const partID = Identifier.ascending("part")
        await Session.updatePart({
          id: partID,
          messageID: ctx.messageID,
          sessionID: ctx.sessionID,
          type: "tool",
          tool: call.tool,
          callID: partID,
          state: {
            status: "error",
            input: call.parameters,
            error: "Maximum of 25 tools allowed in batch",
            time: { start: now, end: now },
          },
        })
        results.push({
          success: false as const,
          tool: call.tool,
          error: new Error("Maximum of 25 tools allowed in batch"),
        })
      }

      const successfulCalls = results.filter((r) => r.success).length
      const failedCalls = results.length - successfulCalls

      const outputMessage =
        failedCalls > 0
          ? `Executed ${successfulCalls}/${results.length} tools successfully. ${failedCalls} failed.`
          : `All ${successfulCalls} tools executed successfully.\n\nKeep using the batch tool for optimal performance in your next response!`

      return {
        title: `Batch execution (${successfulCalls}/${results.length} successful)`,
        output: outputMessage,
        attachments: results.filter((result) => result.success).flatMap((r) => r.result.attachments ?? []),
        metadata: {
          totalCalls: results.length,
          successful: successfulCalls,
          failed: failedCalls,
          tools: params.tool_calls.map((c) => c.tool),
          details: results.map((r) => ({ tool: r.tool, success: r.success })),
        },
      }
    },
  }
})
