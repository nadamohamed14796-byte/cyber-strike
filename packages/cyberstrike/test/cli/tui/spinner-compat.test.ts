import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"

test("TUI spinner components use built-in OpenTUI primitives", async () => {
  const files = [
    path.resolve(import.meta.dir, "../../../src/cli/cmd/tui/component/spinner.tsx"),
    path.resolve(import.meta.dir, "../../../src/cli/cmd/tui/component/prompt/index.tsx"),
  ]

  const sources = await Promise.all(files.map((file) => fs.readFile(file, "utf8")))
  for (const source of sources) {
    expect(source).not.toContain('import "opentui-spinner/solid"')
    expect(source).not.toMatch(/<spinner(?:\s|\/)/)
  }
})
