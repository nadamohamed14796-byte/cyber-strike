import { BusEvent } from "@/bus/bus-event"
import { Bus } from "@/bus"
import z from "zod"
import { Database, eq, asc } from "../storage/db"
import { TodoTable } from "./session.sql"

export namespace Todo {
  export const Info = z
    .object({
      content: z.string().describe("Brief description of the task"),
      status: z.string().describe("Current status of the task: pending, in_progress, completed, cancelled"),
      priority: z.string().describe("Priority level of the task: high, medium, low"),
    })
    .meta({ ref: "Todo" })
  export type Info = z.infer<typeof Info>

  export const Event = {
    Updated: BusEvent.define(
      "todo.updated",
      z.object({
        sessionID: z.string(),
        todos: z.array(Info),
      }),
    ),
  }

  const MAX_COMPLETED = 5
  const isReconChecklistItem = (todo: Info) => /^\\[recon:[a-z_]+\\]/.test(todo.content.trim())

  export function update(input: { sessionID: string; todos: Info[] }) {
    // Retain the whole compact recon checklist so completed steps remain visible
    // while the workflow runs. General completed todos still use the normal short history.
    const active = input.todos.filter((t) => t.status !== "completed" && t.status !== "cancelled")
    const done = input.todos.filter((t) => t.status === "completed" || t.status === "cancelled")
    const reconDone = done.filter(isReconChecklistItem)
    const otherDone = done.filter((t) => !isReconChecklistItem(t))
    const trimmed = [...active, ...reconDone, ...otherDone.slice(-MAX_COMPLETED)]

    Database.transaction((db) => {
      db.delete(TodoTable).where(eq(TodoTable.session_id, input.sessionID)).run()
      if (trimmed.length === 0) return
      db.insert(TodoTable)
        .values(
          trimmed.map((todo, position) => ({
            session_id: input.sessionID,
            content: todo.content,
            status: todo.status,
            priority: todo.priority,
            position,
          })),
        )
        .run()
    })
    Bus.publish(Event.Updated, { sessionID: input.sessionID, todos: trimmed })
  }

  export function get(sessionID: string) {
    const rows = Database.use((db) =>
      db.select().from(TodoTable).where(eq(TodoTable.session_id, sessionID)).orderBy(asc(TodoTable.position)).all(),
    )
    return rows.map((row) => ({
      content: row.content,
      status: row.status,
      priority: row.priority,
    }))
  }
}
