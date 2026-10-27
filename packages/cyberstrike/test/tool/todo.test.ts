import { describe, expect, test } from "bun:test"
import { mergeTodoSnapshot } from "../../src/tool/todo"
import type { Todo } from "../../src/session/todo"

const item = (content: string, status: string, priority = "medium"): Todo.Info => ({
  content,
  status,
  priority,
})

describe("todo snapshot reconciliation", () => {
  test("preserves unfinished tasks omitted from a rewritten snapshot", () => {
    const previous = [
      item("Collect JavaScript files", "pending", "high"),
      item("Analyze endpoints", "in_progress", "high"),
      item("Old completed task", "completed"),
    ]

    const result = mergeTodoSnapshot(previous, [item("Collect JavaScript files", "pending", "high")])

    expect(result.todos).toEqual([
      item("Collect JavaScript files", "pending", "high"),
      item("Analyze endpoints", "in_progress", "high"),
    ])
    expect(result.preserved.map((todo) => todo.content)).toEqual(["Analyze endpoints"])
  })

  test("does not regress an in-progress task to pending", () => {
    const result = mergeTodoSnapshot(
      [item("Verify output files", "in_progress", "high")],
      [item("Verify output files", "pending", "high")],
    )

    expect(result.todos).toEqual([item("Verify output files", "in_progress", "high")])
    expect(result.preserved).toEqual([])
  })

  test("respects an explicit cancellation and does not restore the cancelled task", () => {
    const result = mergeTodoSnapshot(
      [item("Run obsolete check", "pending", "low")],
      [item("Run obsolete check", "cancelled", "low")],
    )

    expect(result.todos).toEqual([item("Run obsolete check", "cancelled", "low")])
    expect(result.preserved).toEqual([])
  })

  test("does not resurrect completed tasks omitted from the snapshot", () => {
    const result = mergeTodoSnapshot(
      [item("Already verified", "completed")],
      [item("New task", "pending", "high")],
    )

    expect(result.todos).toEqual([item("New task", "pending", "high")])
    expect(result.preserved).toEqual([])
  })
})
