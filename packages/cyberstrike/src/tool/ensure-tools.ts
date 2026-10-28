import z from "zod"
import { Tool } from "./tool"

const OfficialInstall = z.object({
  tool: z.string().min(1).max(100),
  method: z.enum(["apt", "brew", "go", "pipx", "cargo", "npm"]),
  package: z.string().min(1).max(200),
  executable: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$/),
  source_url: z.string().url(),
  verify_args: z.array(z.string().max(100)).min(1).max(8),
})

type InstallMethod = z.infer<typeof OfficialInstall>["method"]

export function officialInstallArgs(method: InstallMethod, pkg: string): [string, string[]] | null {
  if (!/^[A-Za-z0-9@][A-Za-z0-9@._+/:=-]{0,199}$/.test(pkg) || pkg.includes("..") || pkg.includes("//")) return null
  switch (method) {
    case "apt": return ["apt-get", ["install", "-y", "--", pkg]]
    case "brew": return ["brew", ["install", pkg]]
    case "go": return ["go", ["install", pkg]]
    case "pipx": return ["pipx", ["install", pkg]]
    case "cargo": return ["cargo", ["install", pkg]]
    case "npm": return ["npm", ["install", "--global", pkg]]
  }
}

function commandPath(command: string) {
  return Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; command -v "${command}"`])
}

function upstreamUrlIsSafe(value: string): boolean {
  try {
    const url = new URL(value)
    return url.protocol === "https:" && !url.username && !url.password
  } catch {
    return false
  }
}

const TOOL_INSTALL_MAP: Record<string, { check: string; install: string; description: string; verify?: string }> = {
  nmap: { check: "nmap", install: "if command -v brew >/dev/null 2>&1; then brew install nmap; else apt-get update && apt-get install -y nmap; fi", description: "Network scanner" },
  nuclei: {
    check: "nuclei",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    description: "Vulnerability scanner",
  },
  ffuf: { check: "ffuf", install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/ffuf/ffuf/v2@latest", description: "Web fuzzer" },
  httpx: {
    check: "httpx",
    // Reject a same-named but incompatible Python HTTPX CLI.
    verify: "httpx -version",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    description: "ProjectDiscovery HTTP toolkit",
  },
  subfinder: {
    check: "subfinder",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    description: "Subdomain discovery",
  },
  amass: {
    check: "amass",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install -v github.com/owasp-amass/amass/v4/...@master",
    description: "Attack surface mapping",
  },
  assetfinder: {
    check: "assetfinder",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/tomnomnom/assetfinder@latest",
    description: "Passive subdomain discovery",
  },
  sublist3r: {
    check: "sublist3r",
    install: "apt-get update && apt-get install -y sublist3r || (command -v pipx >/dev/null 2>&1 && pipx install Sublist3r)",
    description: "Subdomain discovery using search engines",
  },
  findomain: {
    check: "findomain",
    install: "apt-get update && apt-get install -y findomain || cargo install findomain",
    description: "Subdomain discovery",
  },
  waybackurls: {
    check: "waybackurls",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/tomnomnom/waybackurls@latest",
    description: "Wayback Machine URL fetcher",
  },
  gau: { check: "gau", install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/lc/gau/v2/cmd/gau@latest", description: "URL aggregator" },
  hakrawler: {
    check: "hakrawler",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/hakluke/hakrawler@latest",
    description: "Web crawler",
  },
  katana: {
    check: "katana",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/projectdiscovery/katana/cmd/katana@latest",
    description: "Next-gen crawler",
  },
  dalfox: { check: "dalfox", install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/hahwul/dalfox/v2@latest", description: "XSS scanner" },
  sqlmap: { check: "sqlmap", install: "apt-get update && apt-get install -y sqlmap || (if ! command -v pipx >/dev/null 2>&1; then apt-get update && apt-get install -y pipx || exit $?; fi; export PATH=\"$PATH:$HOME/.local/bin\"; pipx install sqlmap)", description: "SQL injection tool" },
  nikto: {
    check: "nikto",
    install: "if command -v brew >/dev/null 2>&1; then brew install nikto; else apt-get update && apt-get install -y nikto; fi",
    description: "Web server scanner",
  },
  wpscan: { check: "wpscan", install: "gem install wpscan || brew install wpscan", description: "WordPress scanner" },
  gospider: {
    check: "gospider",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/jaeles-project/gospider@latest",
    description: "Web spidering",
  },
  arjun: { check: "arjun", install: "if ! command -v pipx >/dev/null 2>&1; then apt-get update && apt-get install -y pipx || exit $?; fi; export PATH=\"$PATH:$HOME/.local/bin\"; pipx install arjun", description: "Parameter discovery" },
  paramspider: { check: "paramspider", install: "if ! command -v pipx >/dev/null 2>&1; then apt-get update && apt-get install -y pipx || exit $?; fi; export PATH=\"$PATH:$HOME/.local/bin\"; pipx install paramspider", description: "Parameter mining" },
  commix: { check: "commix", install: "apt-get update && apt-get install -y commix || (if ! command -v pipx >/dev/null 2>&1; then apt-get update && apt-get install -y pipx || exit $?; fi; export PATH=\"$PATH:$HOME/.local/bin\"; pipx install commix)", description: "Command injection" },
  ssrfmap: { check: "ssrfmap", install: "if ! command -v pipx >/dev/null 2>&1; then apt-get update && apt-get install -y pipx || exit $?; fi; export PATH=\"$PATH:$HOME/.local/bin\"; pipx install ssrfmap", description: "SSRF exploitation" },
  nosqlmap: { check: "nosqlmap", install: "if ! command -v pipx >/dev/null 2>&1; then apt-get update && apt-get install -y pipx || exit $?; fi; export PATH=\"$PATH:$HOME/.local/bin\"; pipx install nosqlmap", description: "NoSQL injection" },
  crlfuzz: {
    check: "crlfuzz",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    description: "CRLF injection scanner",
  },
  gitdumper: { check: "git-dumper", install: "if ! command -v pipx >/dev/null 2>&1; then apt-get update && apt-get install -y pipx || exit $?; fi; export PATH=\"$PATH:$HOME/.local/bin\"; pipx install git-dumper", description: "Git repository dumper" },
}

export const EnsureToolsTool = Tool.define("ensure_tools", {
  description: [
    "Exact CLI installer for an already-selected recon/security method; it is not the tool selector.",
    "When a selected CLI is missing or incompatible, install that exact CLI rather than silently replacing it with a lower-coverage alternative. Use the predefined recipe when catalogued.",
    "For an uncatalogued CLI, first inspect the official upstream installation instructions, then pass official_installs with the exact package-manager method, package identifier, expected executable, official HTTPS source URL, and documented version/help arguments. Do not pass shell commands or guessed package names.",
    "If exact installation fails or prerequisites are unavailable, preserve the real error and report the blocker. Only then may the orchestrator choose a different method and explain the coverage trade-off. Never install every catalog example, and never install tools for passive questions, code review, or informational requests.",
  ].join("\n"),
  parameters: z.object({
    tools: z.array(z.string().min(1).max(100)).describe(`Exact selected CLI names to check/install. Catalogued recipes: ${Object.keys(TOOL_INSTALL_MAP).join(", ")}.`),
    official_installs: z.array(OfficialInstall).optional().describe("Reviewed upstream install details for exact selected tools missing from the catalog. These describe a package-manager method, never a shell command."),
  }),
  async execute(params) {
    const results: Array<{ tool: string; installed: boolean; action: string }> = []

    for (const name of params.tools) {
      const spec = TOOL_INSTALL_MAP[name]
      if (!spec) {
        if (!/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,99}$/.test(name)) {
          results.push({ tool: name, installed: false, action: "Invalid exact CLI name; no installation attempted" })
          continue
        }
        const official = params.official_installs?.find((item) => item.tool === name)
        if (!official) {
          const present = commandPath(name)
          const location = present.exitCode === 0 ? present.stdout.toString().trim() : ""
          results.push({
            tool: name,
            installed: false,
            action: location
              ? "Executable found at " + location + " but its identity/version is not verified. Review the official upstream instructions and call ensure_tools with official_installs for this exact CLI."
              : "CLI is not catalogued and is not on PATH. Review its official upstream installation instructions, then call ensure_tools again with official_installs for this exact CLI; do not substitute another tool.",
          })
          continue
        }
        if (official.executable !== name || !upstreamUrlIsSafe(official.source_url)) {
          results.push({ tool: name, installed: false, action: "Rejected install details: executable must match the selected CLI and source_url must be a credential-free HTTPS upstream reference" })
          continue
        }
        const existingPath = commandPath(official.executable)
        if (existingPath.exitCode === 0) {
          const executablePath = existingPath.stdout.toString().trim()
          const identity = Bun.spawnSync([executablePath, ...official.verify_args], { timeout: 30_000 })
          if (identity.exitCode === 0) {
            const identityOutput = (identity.stdout.toString().trim() || identity.stderr.toString().trim()).slice(0, 240)
            results.push({ tool: name, installed: true, action: "Already installed and verified " + executablePath + (identityOutput ? " (" + identityOutput + ")" : "") + "; source: " + official.source_url })
            continue
          }
        }
        const command = officialInstallArgs(official.method, official.package)
        if (!command) {
          results.push({ tool: name, installed: false, action: "Rejected unsafe package identifier; supply only the package/module name from the official docs" })
          continue
        }
        const [manager, args] = command
        let managerResult = commandPath(manager)
        const prerequisitePackages: Partial<Record<InstallMethod, string>> = {
          go: "golang-go",
          pipx: "pipx",
          cargo: "cargo",
          npm: "npm",
        }
        if (managerResult.exitCode !== 0 && prerequisitePackages[official.method]) {
          const apt = commandPath("apt-get")
          if (apt.exitCode === 0) {
            const aptPath = apt.stdout.toString().trim()
            const update = Bun.spawnSync([aptPath, "update"], { timeout: 600_000 })
            if (update.exitCode === 0) {
              Bun.spawnSync([aptPath, "install", "-y", "--", prerequisitePackages[official.method]!], { timeout: 600_000 })
            }
            managerResult = commandPath(manager)
          }
        }
        if (managerResult.exitCode !== 0) {
          results.push({ tool: name, installed: false, action: "Required package manager " + manager + " is unavailable; exact CLI not installed. Official instructions: " + official.source_url })
          continue
        }
        const managerPath = managerResult.stdout.toString().trim()
        if (official.method === "apt") {
          const update = Bun.spawnSync([managerPath, "update"], { timeout: 600_000 })
          if (update.exitCode !== 0) {
            const detail = update.stderr.toString().trim().slice(0, 200) || update.stdout.toString().trim().slice(-200)
            results.push({ tool: name, installed: false, action: "apt repository update failed: " + (detail || "unknown package-manager error") })
            continue
          }
        }
        const install = Bun.spawnSync([managerPath, ...args], { timeout: 600_000 })
        const verifiedPath = commandPath(official.executable)
        if (install.exitCode !== 0 || verifiedPath.exitCode !== 0) {
          const detail = install.stderr.toString().trim().slice(0, 240) || install.stdout.toString().trim().slice(-240)
          results.push({
            tool: name,
            installed: false,
            action: (detail || "Package installation did not produce the expected executable") + ". Official instructions: " + official.source_url,
          })
          continue
        }
        const executablePath = verifiedPath.stdout.toString().trim()
        const identity = Bun.spawnSync([executablePath, ...official.verify_args], { timeout: 30_000 })
        if (identity.exitCode !== 0) {
          const detail = identity.stderr.toString().trim().slice(0, 200) || identity.stdout.toString().trim().slice(-200)
          results.push({ tool: name, installed: false, action: "Executable was installed but documented identity/version check failed: " + (detail || official.verify_args.join(" ")) })
          continue
        }
        const identityOutput = (identity.stdout.toString().trim() || identity.stderr.toString().trim()).slice(0, 240)
        results.push({
          tool: name,
          installed: true,
          action: "Installed and verified " + executablePath + (identityOutput ? " (" + identityOutput + ")" : "") + "; source: " + official.source_url,
        })
        continue
      }

      // Check if installed
      const check = Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; command -v ${spec.check}`])
      if (check.exitCode === 0) {
        const executable = check.stdout.toString().trim()
        const identity = spec.verify ? Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; ${spec.verify} >/dev/null 2>&1`]) : undefined
        if (!identity || identity.exitCode === 0) {
          results.push({ tool: name, installed: true, action: `Already installed and verified: ${executable}` })
          continue
        }
        // Same-named but incompatible CLI (notably httpx) is not usable.
      }

      // Try to install
      const install = Bun.spawnSync(["sh", "-lc", `${spec.install}; status=$?; export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; exit $status`], { timeout: 600_000 })
      // Installation exit status alone is not proof that the command is usable.
      const verify = Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; command -v ${spec.check}`])
      const identity = spec.verify ? Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; ${spec.verify} >/dev/null 2>&1`]) : undefined
      if (install.exitCode === 0 && verify.exitCode === 0 && (!identity || identity.exitCode === 0)) {
        results.push({ tool: name, installed: true, action: `Installed and verified: ${verify.stdout.toString().trim()}` })
      } else {
        const stderr = install.stderr.toString().trim().slice(0, 200)
        const stdout = install.stdout.toString().trim().slice(-200)
        const reason = install.exitCode !== 0 ? (stderr || stdout || `installer exited ${install.exitCode}`) : `installer completed but ${spec.check} is still not on PATH`
        results.push({ tool: name, installed: false, action: `Install failed: ${reason}` })
      }
    }

    const installed = results.filter((r) => r.installed).length
    const failed = results.filter((r) => !r.installed).length

    const output = [
      `Tool check: ${installed} ready, ${failed} failed`,
      "",
      ...results.map((r) => `${r.installed ? "[OK]" : "[FAIL]"} ${r.tool}: ${r.action}`),
    ]

    return {
      title: `Tools: ${installed}/${results.length} ready`,
      output: output.join("\n"),
      metadata: { installed, failed, results },
    }
  },
})
