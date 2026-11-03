import { test, expect } from "../fixtures"
import { withSession } from "../actions"

test("discovers an existing extension broker child and opens new task turns", async ({ page, sdk, gotoSession }) => {
  const title = `e2e extension parent ${Date.now()}`

  await withSession(sdk, title, async (parent) => {
    const broker = await sdk.session
      .create({ parentID: parent.id, title: "Extension Agent Tasks" })
      .then((result) => result.data)
    if (!broker?.id) throw new Error("Extension broker session create did not return an id")

    try {
      // Create the broker before opening the parent page: no live session.created
      // event can populate the root-only session index for this existing child.
      await gotoSession(parent.id)
      const panel = page.getByRole("region", { name: "Extension Agent tasks" })
      await expect(panel).toBeVisible({ timeout: 30_000 })

      // A new child user turn must update the synced transcript and open the
      // broker session from the parent view without requiring an HTTP request row.
      await sdk.session.promptAsync({
        sessionID: broker.id,
        noReply: true,
        parts: [{ type: "text", text: "extension broker auto-open regression" }],
      })
      await expect(page).toHaveURL(new RegExp(`/session/${broker.id}$`), { timeout: 30_000 })
    } finally {
      await sdk.session.delete({ sessionID: broker.id }).catch(() => undefined)
    }
  })
})
