import { describe, expect, test } from "bun:test"
import { Actor } from "./actor"
import { Workspace } from "./workspace"

describe("workspace deletion authorization", () => {
  test("rejects workspace deletion by a member before touching the database", async () => {
    await expect(
      Actor.provide(
        "user",
        {
          userID: "user_test",
          workspaceID: "workspace_test",
          accountID: "account_test",
          role: "member",
        },
        () => Workspace.remove.force(undefined),
      ),
    ).rejects.toThrow(/admin/i)
  })
})
