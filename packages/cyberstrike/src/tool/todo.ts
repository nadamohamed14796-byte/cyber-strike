import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION_WRITE from "./todowrite.txt"
import { Todo } from "../session/todo"

function nextTodo(todos: Todo.Info[]) {
  const active = todos.filter((todo) => todo.status === "pending" || todo.status === "in_progress")
  const inProgress = active.find((todo) => todo.status === "in_progress")
  if (inProgress) return inProgress
  const rank: Record<string, number> = { high: 0, medium: 1, low: 2 }
  return active
    .map((todo, index) => ({ todo, index }))
    .sort((a, b) => (rank[a.todo.priority] ?? 3) - (rank[b.todo.priority] ?? 3) || a.index - b.index)[0]?.todo
}

function nextTodoHint(todos: Todo.Info[]) {
  const next = nextTodo(todos)
  if (!next) return "Execution queue is clear: all items are completed or cancelled."
  return "NEXT ACTION — resume this in_progress item or start it now; do not skip it: [" + next.status + ", " + next.priority + "] " + next.content
}

export const TodoWriteTool = Tool.define("todowrite", {
  description: DESCRIPTION_WRITE,
  parameters: z.object({
    todos: z.array(z.object(Todo.Info.shape)).describe("The updated todo list"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "todowrite",
      patterns: ["*"],
      always: ["*"],
      metadata: {},
    })

    const activeCount = params.todos.filter((x) => x.status === "pending" || x.status === "in_progress").length
    if (activeCount > 25) {
      return {
        title: "error",
        output:
          "Cannot have more than 25 active (pending/in_progress) todos. Consolidate related items or complete/cancel existing ones first.",
        metadata: {
          todos: params.todos,
        },
      }
    }

    await Todo.update({
      sessionID: ctx.sessionID,
      todos: params.todos,
    })
    return {
      title: `${params.todos.filter((x) => x.status !== "completed").length} todos`,
      output: JSON.stringify(params.todos, null, 2) + "\n\n" + nextTodoHint(params.todos),
      metadata: {
        todos: params.todos,
      },
    }
  },
})

export const TodoReadTool = Tool.define("todoread", {
  description: "Use this tool to read your todo list",
  parameters: z.object({}),
  async execute(_params, ctx) {
    await ctx.ask({
      permission: "todoread",
      patterns: ["*"],
      always: ["*"],
      metadata: {},
    })

    const todos = await Todo.get(ctx.sessionID)
    const active = todos.filter((x) => x.status === "pending" || x.status === "in_progress")
    const doneCount = todos.length - active.length
    const output =
      (doneCount > 0
        ? JSON.stringify(active, null, 2) + `\n\n(${doneCount} completed/cancelled items hidden)`
        : JSON.stringify(active, null, 2)) +
      "\n\n" +
      nextTodoHint(todos)
    return {
      title: `${active.length} todos`,
      metadata: {
        todos,
      },
      output,
    }
  },
})
