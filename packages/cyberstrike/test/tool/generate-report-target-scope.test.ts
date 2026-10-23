import fs from "node:fs/promises"
import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Intel } from "../../src/methodology/intel"
import { Vulnerability } from "../../src/session/vulnerability"
import { TargetMemory } from "../../src/target"
import { GenerateReportTool } from "../../src/tool/generate-report"

function toolContext(sessionID: string) {
  return {
    sessionID,
    messageID: undefined,
    agent: "cyberstrike",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => undefined,
  } as any
}

test("target-scoped reports include authorized descendants but not unrelated workspaces", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const root = await TargetMemory.configureScope("https://example.com", {
        include: ["example.com", "*.example.com"],
        exclude: ["admin.example.com"],
        authorizationSource: "Example authorized program",
        authorizationReference: "https://example.com/security",
      })
      const api = await TargetMemory.registerObservedAsset("https://api.example.com/v1/users", "api")
      expect(api).not.toBeNull()

      const outside = await TargetMemory.configureScope("https://outside.example.test", {
        include: ["outside.example.test"],
        authorizationSource: "Separate authorized program",
        authorizationReference: "https://outside.example.test/security",
      })
      const session = await Session.create({})
      try {
        Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "high",
            title: "Root-only finding",
            description: "An issue on the main application.",
            endpoint: "https://example.com/account",
            target_id: root.workspace.id,
          },
        })
        Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "medium",
            title: "API-only finding",
            description: "An issue on the authorized API asset.",
            endpoint: "https://api.example.com/v1/users/123",
            target_id: api!.id,
          },
        })
        Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "low",
            title: "Outside-program finding",
            description: "This must not leak into the example.com report.",
            endpoint: "https://outside.example.test/admin",
            target_id: outside.workspace.id,
          },
        })

        Intel.add({
          sessionID: session.id,
          data: { type: "endpoint", title: "Root endpoint", asset: "https://example.com/account" },
        })
        Intel.add({
          sessionID: session.id,
          data: { type: "endpoint", title: "API endpoint", asset: "https://api.example.com/v1/users" },
        })
        Intel.add({
          sessionID: session.id,
          data: { type: "endpoint", title: "Outside endpoint", asset: "https://outside.example.test/admin" },
        })

        const tool = await GenerateReportTool.init()
        const programReport = await tool.execute({
          target_url: "https://example.com",
          include_children: true,
          include_sections: ["findings", "coverage", "attack_surface", "validation"],
        }, toolContext(session.id))

        expect(programReport.output).toContain("Root-only finding")
        expect(programReport.output).toContain("API-only finding")
        expect(programReport.output).not.toContain("Outside-program finding")
        expect(programReport.output).toContain("Root endpoint")
        expect(programReport.output).toContain("API endpoint")
        expect(programReport.output).not.toContain("Outside endpoint")
        expect(programReport.output).toContain("Not computed for this target-limited report")
        expect(programReport.metadata.findingCount).toBe(2)
        expect(programReport.metadata.excludedFindingCount).toBe(1)
        expect(programReport.metadata.includedWorkspaceIDs).toContain(root.workspace.id)
        expect(programReport.metadata.includedWorkspaceIDs).toContain(api!.id)

        const apiReport = await tool.execute({
          target_url: api!.targetURL,
          include_children: false,
          include_sections: ["findings", "coverage", "attack_surface"],
        }, toolContext(session.id))
        expect(apiReport.output).not.toContain("Root-only finding")
        expect(apiReport.output).toContain("API-only finding")
        expect(apiReport.output).not.toContain("Outside-program finding")
        expect(apiReport.output).toContain("Total Intel Entries: 1")
        expect(apiReport.metadata.findingCount).toBe(1)
        expect(apiReport.metadata.includedWorkspaceIDs).toEqual([api!.id])
        expect(apiReport.metadata.recommendedReportPath).toContain(api!.relativePath + "/reports/security-final.md")
        expect(apiReport.metadata.automaticallySaved).toBe(true)
        const savedChildReport = await fs.readFile(apiReport.metadata.recommendedReportPath as string, "utf-8")
        expect(savedChildReport).toContain("API-only finding")
        expect(savedChildReport).not.toContain("Root-only finding")

        const repeatedApiReport = await tool.execute({
          target_url: api!.targetURL,
          include_children: false,
          include_sections: ["findings", "coverage", "attack_surface"],
        }, toolContext(session.id))
        expect(repeatedApiReport.metadata.recommendedReportPath).toBe(apiReport.metadata.recommendedReportPath)
        expect(await fs.readdir(path.join(api!.workspacePath, "reports"))).toEqual(["security-final.md"])
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})


test("generate_report defaults to the only observed root target and saves a workspace report", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const root = await TargetMemory.configureScope("https://single-program.example.test", {
        include: ["single-program.example.test", "*.single-program.example.test"],
        authorizationSource: "Single program",
        authorizationReference: "https://single-program.example.test/security",
      })
      const child = await TargetMemory.registerObservedAsset("https://api.single-program.example.test/v1", "api")
      expect(child).not.toBeNull()
      const session = await Session.create({})
      try {
        Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "high",
            title: "Scoped auto-report finding",
            description: "A finding attributed to one authorized program.",
            endpoint: "https://api.single-program.example.test/v1/users",
            target_id: child!.id,
          },
        })
        const tool = await GenerateReportTool.init()
        const result = await tool.execute({
          include_sections: ["findings"],
        }, toolContext(session.id))
        expect(result.metadata.reportTargetURL).toBe(root.workspace.targetURL)
        expect(result.metadata.includedWorkspaceIDs).toContain(child!.id)
        expect(result.metadata.automaticallySaved).toBe(true)
        const reportPath = result.metadata.recommendedReportPath as string
        expect(reportPath).toContain(root.workspace.relativePath + "/reports/security-final.md")
        const saved = await fs.readFile(reportPath, "utf-8")
        expect(saved).toContain("Scoped auto-report finding")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("generate_report refuses to silently mix multiple observed root programs", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const roots = await Promise.all([
        TargetMemory.configureScope("https://program-a.example.test", {
          include: ["program-a.example.test"],
          authorizationSource: "Program A",
          authorizationReference: "https://program-a.example.test/security",
        }),
        TargetMemory.configureScope("https://program-b.example.test", {
          include: ["program-b.example.test"],
          authorizationSource: "Program B",
          authorizationReference: "https://program-b.example.test/security",
        }),
      ])
      const session = await Session.create({})
      try {
        for (const [index, root] of roots.entries()) {
          Vulnerability.add({
            sessionID: session.id,
            data: {
              severity: "medium",
              title: "Program " + (index ? "B" : "A") + " finding",
              description: "Finding from a different root target.",
              endpoint: root.workspace.targetURL + "/account",
              target_id: root.workspace.id,
            },
          })
        }
        const tool = await GenerateReportTool.init()
        await expect(tool.execute({ include_sections: ["findings"] }, toolContext(session.id)))
          .rejects.toThrow(/more than one target program.*target_url/i)
        const selected = await tool.execute({
          target_url: roots[0]!.workspace.targetURL,
          include_children: true,
          include_sections: ["findings"],
        }, toolContext(session.id))
        expect(selected.output).toContain("Program A finding")
        expect(selected.output).not.toContain("Program B finding")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})
