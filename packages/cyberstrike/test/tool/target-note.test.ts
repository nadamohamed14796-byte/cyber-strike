import { expect, test } from "bun:test"
import { TargetNoteTool } from "../../src/tool/target-note"

test("omitting target-note status preserves the existing investigation status on upsert", async () => {
  const tool = await TargetNoteTool.init()
  const parsed = tool.parameters.parse({
    target_url: "https://example.com",
    kind: "finding",
    title: "Authorization boundary",
    content: "The owner can access the record; cross-account access remains untested.",
    identity_key: "finding:auth-boundary",
    upsert_by_identity: true,
  })

  expect(parsed.status).toBeUndefined()
  expect(parsed.upsert_by_identity).toBe(true)
})


test("target-note exposes current and append-only journal modes", async () => {
  const tool = await TargetNoteTool.init()
  const current = tool.parameters.parse({
    target_url: "https://example.com",
    title: "Endpoint behavior",
    content: "Current understanding of the endpoint.",
    identity_key: "endpoint:/api/me:behavior",
  })
  const journal = tool.parameters.parse({
    target_url: "https://example.com",
    record_mode: "journal",
    title: "Endpoint behavior experiment",
    content: "Changed one input under the same conditions; the response remained unchanged.",
    identity_key: "endpoint:/api/me:behavior",
  })

  expect(current.record_mode).toBe("current")
  expect(journal.record_mode).toBe("journal")
  expect(journal.identity_key).toBe("endpoint:/api/me:behavior")
})
