import { describe, expect, test } from "bun:test"
import { SessionPrompt } from "../../src/session/prompt"

describe("command argument substitution", () => {
  test("preserves multiline source code and replacement tokens literally", () => {
    const source = ["$&", "$'", "$`", "$ARGUMENTS"].join("\n")

    expect(SessionPrompt.substituteCommandArguments("Code:\n$ARGUMENTS\nEnd", source)).toBe(
      "Code:\n" + source + "\nEnd",
    )
  })

  test("replaces every placeholder while preserving the supplied text", () => {
    const source = "line one\n$& and $ARGUMENTS\nline three"

    expect(SessionPrompt.substituteCommandArguments("$ARGUMENTS\n$ARGUMENTS", source)).toBe(
      source + "\n" + source,
    )
  })
})
