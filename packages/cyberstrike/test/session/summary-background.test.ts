import { describe, expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { SessionSummary } from "../../src/session/summary"
import { tmpdir } from "../fixture/fixture"

describe("background session summary failure isolation", () => {
  test("does not reject when the summarized user message no longer exists", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await Session.create({ title: "summary-failure-isolation-test" })

        await expect(
          SessionSummary.summarize({
            sessionID: session.id,
            messageID: "message_that_does_not_exist",
          }),
        ).resolves.toBeUndefined()

        await Session.remove(session.id)
      },
    })
  })
})
