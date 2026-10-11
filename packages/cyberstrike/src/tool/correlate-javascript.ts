import z from "zod"
import { Tool } from "./tool"
import { JavaScriptCorrelation } from "../target/javascript-correlation"

export const CorrelateJavaScriptTool = Tool.define("correlate_javascript", {
  description: [
    "Correlate already-captured JavaScript asset information with stored endpoints, requests/responses, request observations, web functions, and findings.",
    "This performs no network requests and does not execute JavaScript. It reads only the current session and descendant-agent data, then persists a redacted correlation snapshot to the per-target workspace and SQLite target notes.",
    "Pass the authorized target URL. Optionally pass a JavaScript file URL to narrow the correlation to that file; otherwise it uses JavaScript-like Intel assets already recorded for the target host.",
    "Same-host matches are labelled candidate relationships, not proof that a script issued a request. Foreign-key relationships from web_function/request_observation to a captured request are direct relationships.",
    "Do not provide URL credentials, session tokens, or other secrets. This tool does not replace the existing scope enforcement.",
  ].join("\n"),
  parameters: z.object({
    target_url: z.string().min(1).describe("Target URL already approved for the current session"),
    javascript_url: z.string().url().optional().describe("Optional observed HTTP(S) JavaScript asset URL"),
  }),
  async execute(params, ctx) {
    try {
      const result = await JavaScriptCorrelation.build({
        sessionID: ctx.sessionID,
        targetURL: params.target_url,
        javascriptURL: params.javascript_url,
      })
      const graph = result.graph
      return {
        title: "JavaScript correlation saved",
        output: [
          "Target workspace: " + result.workspacePath,
          "Graph JSON: " + result.graphPath,
          "Saved note ID: " + result.noteID,
          "JavaScript assets: " + graph.javascriptAssets.length,
          "Related requests/responses: " + graph.requests.length,
          "Web functions: " + graph.webFunctions.length,
          "Request observations: " + graph.observations.length,
          "Potentially related findings: " + graph.findings.length,
          "Graph edges: " + graph.edges.length,
          ...graph.notes.map((note) => "- " + note),
        ].join("\n"),
        metadata: {
          graph_path: result.graphPath,
          target_workspace: result.workspacePath,
          javascript_assets: graph.javascriptAssets.length,
          requests: graph.requests.length,
          web_functions: graph.webFunctions.length,
          observations: graph.observations.length,
          findings: graph.findings.length,
          edges: graph.edges.length,
        },
      }
    } catch (error) {
      return {
        title: "JavaScript correlation failed",
        output: error instanceof Error ? error.message : String(error),
        metadata: { correlation_error: true },
      }
    }
  },
})
