import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION_WRITE from "./todowrite.txt"
import { Todo } from "../session/todo"

export function mergeTodoSnapshot(previous: Todo.Info[], incoming: Todo.Info[]) {
  const next = incoming.map((todo) => {
    const prior = previous.find((item) => item.content.trim() === todo.content.trim())
    if (prior?.status === "in_progress" && todo.status === "pending") {
      return { ...todo, status: "in_progress" }
    }
    return todo
  })
  const hasTodo = (content: string) => next.some((todo) => todo.content.trim() === content.trim())
  const preserved = previous.filter(
    (todo) =>
      (todo.status === "pending" || todo.status === "in_progress") &&
      !hasTodo(todo.content),
  )
  return { todos: [...next, ...preserved], preserved }
}

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

    const previous = await Todo.get(ctx.sessionID)
    // An update is a full snapshot. Preserve unfinished work unless the agent
    // explicitly keeps it or marks it cancelled; omission must not erase work.
    const { todos: nextTodos, preserved } = mergeTodoSnapshot(previous, params.todos)

    const activeCount = nextTodos.filter((x) => x.status === "pending" || x.status === "in_progress").length
    if (activeCount > 25) {
      return {
        title: "error",
        output:
          "Cannot have more than 25 active (pending/in_progress) todos. Consolidate related items or explicitly cancel completed/irrelevant work first.",
        metadata: {
          todos: nextTodos,
        },
      }
    }

    await Todo.update({
      sessionID: ctx.sessionID,
      todos: nextTodos,
    })
    return {
      title: `${nextTodos.filter((x) => x.status === "pending" || x.status === "in_progress").length} active todos`,
      output:
        JSON.stringify(nextTodos, null, 2) +
        (preserved.length ? "\n\nPreserved unfinished items omitted from this update: " + preserved.map((todo) => todo.content).join(" | ") : "") +
        "\n\n" +
        nextTodoHint(nextTodos),
      metadata: {
        todos: nextTodos,
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
    const visible = todos.filter((x) => x.status === "pending" || x.status === "in_progress" || /^\\[recon:[a-z_]+\\]/.test(x.content.trim()))
    const doneCount = todos.length - visible.length
    const output =
      (doneCount > 0
        ? JSON.stringify(visible, null, 2) + `\n\n(${doneCount} other completed/cancelled items hidden)`
        : JSON.stringify(visible, null, 2)) +
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
