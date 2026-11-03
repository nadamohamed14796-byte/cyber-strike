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

  test("normalizes content and removes duplicate identities", () => {
    const result = mergeTodoSnapshot([], [
      item("  Inspect API authorization  ", "pending", "high"),
      item("Inspect API authorization", "completed", "low"),
    ])

    expect(result.todos).toEqual([item("Inspect API authorization", "pending", "high")])
    expect(result.preserved).toEqual([])
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

  test("preserves completed recon checklist entries omitted from later snapshots", () => {
    const completed = item("[recon:javascript_analysis] Analyze every JavaScript asset", "completed", "high")
    const result = mergeTodoSnapshot(
      [completed, item("Ordinary completed task", "completed")],
      [item("[recon:endpoint_inventory] Build endpoint inventory", "pending", "high")],
    )

    expect(result.todos).toEqual([
      item("[recon:endpoint_inventory] Build endpoint inventory", "pending", "high"),
      completed,
    ])
    expect(result.preserved).toEqual([completed])
  })
})
