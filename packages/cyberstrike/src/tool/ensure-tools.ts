import z from "zod"
import { Tool } from "./tool"

const TOOL_INSTALL_MAP: Record<string, { check: string; install: string; description: string }> = {
  nmap: { check: "nmap", install: "if command -v brew >/dev/null 2>&1; then brew install nmap; else apt-get update && apt-get install -y nmap; fi", description: "Network scanner" },
  nuclei: {
    check: "nuclei",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    description: "Vulnerability scanner",
  },
  ffuf: { check: "ffuf", install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/ffuf/ffuf/v2@latest", description: "Web fuzzer" },
  httpx: {
    check: "httpx",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    description: "HTTP toolkit",
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
  sqlmap: { check: "sqlmap", install: "pip3 install sqlmap", description: "SQL injection tool" },
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
  arjun: { check: "arjun", install: "pip3 install arjun", description: "Parameter discovery" },
  paramspider: { check: "paramspider", install: "pip3 install paramspider", description: "Parameter mining" },
  commix: { check: "commix", install: "pip3 install commix", description: "Command injection" },
  ssrfmap: { check: "ssrfmap", install: "pip3 install ssrfmap", description: "SSRF exploitation" },
  nosqlmap: { check: "nosqlmap", install: "pip3 install nosqlmap", description: "NoSQL injection" },
  crlfuzz: {
    check: "crlfuzz",
    install: "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    description: "CRLF injection scanner",
  },
  gitdumper: { check: "git-dumper", install: "pip3 install git-dumper", description: "Git repository dumper" },
}

export const EnsureToolsTool = Tool.define("ensure_tools", {
  description:
    "On an explicitly requested authorized pentest, recon run, vulnerability scan, or active security test, use this whenever a useful tool is missing before abandoning that method. Select only tools justified by the current evidence gap; this is not a fixed phase checklist. Install from the predefined trusted recipes, then verify the executable is actually available on PATH and report any missing prerequisite or failure. If a tool is not in the catalog, do not guess or execute an untrusted install command: report that no verified recipe exists and continue with an installed equivalent where possible. Never install tools for passive questions, code review, or informational requests.",
  parameters: z.object({
    tools: z
      .array(z.string())
      .describe(`Optional candidates to check/install; names supported by this installer only. This is not a list of required tools. Available: ${Object.keys(TOOL_INSTALL_MAP).join(", ")}`),
  }),
  async execute(params) {
    const results: Array<{ tool: string; installed: boolean; action: string }> = []

    for (const name of params.tools) {
      const spec = TOOL_INSTALL_MAP[name]
      if (!spec) {
        // Safe fallback: install a same-named package only from the configured OS
        // package repository. Never interpret model-provided names as shell syntax.
        if (!/^[a-zA-Z0-9][a-zA-Z0-9+.-]{0,99}$/.test(name)) {
          results.push({ tool: name, installed: false, action: "No trusted install recipe; invalid package name" })
          continue
        }
        const already = Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; command -v "${name}"`])
        if (already.exitCode === 0) {
          results.push({ tool: name, installed: true, action: `Already installed: ${already.stdout.toString().trim()}` })
          continue
        }
        const packageManager = Bun.spawnSync(["sh", "-lc", "command -v apt-get"])
        if (packageManager.exitCode !== 0) {
          results.push({ tool: name, installed: false, action: "No trusted install recipe for this tool and apt-get is unavailable" })
          continue
        }
        const installUnknown = Bun.spawnSync(["sh", "-lc", `apt-get update && apt-get install -y -- "${name}"`], { timeout: 180_000 })
        const verifyUnknown = Bun.spawnSync(["sh", "-lc", `command -v "${name}"`])
        if (installUnknown.exitCode === 0 && verifyUnknown.exitCode === 0) {
          results.push({ tool: name, installed: true, action: `Installed from configured OS package repository: ${verifyUnknown.stdout.toString().trim()}` })
        } else {
          const detail = installUnknown.stderr.toString().trim().slice(0, 200) || installUnknown.stdout.toString().trim().slice(-200)
          results.push({ tool: name, installed: false, action: detail ? `No verified install: ${detail}` : "No trusted install recipe or matching executable after package installation" })
        }
        continue
      }

      // Check if installed
      const check = Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; command -v ${spec.check}`])
      if (check.exitCode === 0) {
        results.push({ tool: name, installed: true, action: `Already installed: ${check.stdout.toString().trim()}` })
        continue
      }

      // Try to install
      const install = Bun.spawnSync(["sh", "-lc", `${spec.install}; status=$?; export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; exit $status`], { timeout: 180_000 })
      // Installation exit status alone is not proof that the command is usable.
      const verify = Bun.spawnSync(["sh", "-lc", `export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"; command -v ${spec.check}`])
      if (install.exitCode === 0 && verify.exitCode === 0) {
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
