import { describe, expect, test } from "bun:test"
import { Command } from "../../src/command"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

describe("built-in solve command", () => {
  test("is registered and accepts multiline code arguments", async () => {
    await using tmp = await tmpdir()

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const command = await Command.get("solve")

        expect(command).toBeDefined()
        expect(command).toMatchObject({
          name: "solve",
          description: "solve, debug, explain, review, or improve code in any language",
          source: "command",
        })

        const template = await command!.template
        expect(template).toContain("**Code input:** $ARGUMENTS")
        expect(template).toContain("Preserve multiline code exactly as supplied.")
        expect(Command.hints(template)).toContain("$ARGUMENTS")
      },
    })
  })
})
