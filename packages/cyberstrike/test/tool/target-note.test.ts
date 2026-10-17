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
