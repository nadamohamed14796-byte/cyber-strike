import { describe, expect, test } from "bun:test"
import { officialInstallArgs } from "../../src/tool/ensure-tools"

describe("official exact-tool installation argument construction", () => {
  test("uses package-manager argument arrays for the selected CLI", () => {
    expect(officialInstallArgs("go", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest")).toEqual([
      "go",
      ["install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
    ])
    expect(officialInstallArgs("pipx", "arjun")).toEqual(["pipx", ["install", "arjun"]])
    expect(officialInstallArgs("npm", "@scope/tool")).toEqual(["npm", ["install", "--global", "@scope/tool"]])
    expect(officialInstallArgs("apt", "ffuf")).toEqual(["apt-get", ["install", "-y", "--", "ffuf"]])
  })

  test("rejects shell syntax, whitespace, URL payloads, and malformed package identifiers", () => {
    expect(officialInstallArgs("go", "github.com/example/tool@latest; id")).toBeNull()
    expect(officialInstallArgs("npm", "tool && touch /tmp/pwned")).toBeNull()
    expect(officialInstallArgs("pipx", "https://example.test/install.sh")).toBeNull()
    expect(officialInstallArgs("cargo", "../tool")).toBeNull()
  })
})
