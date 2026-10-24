import z from "zod"
import { Tool } from "./tool"
import { JavaScriptCorrelation } from "../target/javascript-correlation"

const CorrelateJavaScriptParameters = z.object({
    target_url: z.string().min(1).describe("Target URL already approved for the current session"),
    javascript_url: z.string().url().optional().describe("Optional observed HTTP(S) JavaScript asset URL"),
  })

export const CorrelateJavaScriptTool = Tool.define<typeof CorrelateJavaScriptParameters, Tool.Metadata>("correlate_javascript", {
  description: [
    "Correlate already-captured JavaScript asset information with stored endpoints, requests/responses, request observations, web functions, and findings.",
    "Call this after hackbrowser has delivered JavaScript response captures and before detailed endpoint testing. It extracts function and request candidates, parameters, header/auth/cookie signals, secret-like fingerprints and source locations (never raw values), role hints, source-map results, and a pending verification plan into a private target-local attack-surface snapshot. All matches remain unverified candidates.",
    "This performs no network requests and does not execute JavaScript. It reads only the current session and descendant-agent data, then persists a private target-local correlation snapshot and notes. Source-map files already captured in the session are parsed as data; embedded source code is analyzed in memory and is not persisted.",
    "Pass the authorized target URL. Optionally pass a JavaScript file URL to narrow source analysis to that captured file and only its directly referenced source maps; otherwise it considers captured JavaScript/source-map responses and JavaScript-like Intel assets associated with the target's session/workspace. The authoritative persisted scope and workspace-relationship checks decide which assets are eligible, including assets served from a separately hosted CDN.",
    "Same-host matches are labelled candidate relationships, not proof that a script issued a request. Foreign-key relationships from web_function/request_observation to a captured request are direct relationships.",
    "Captured JavaScript response bodies are analyzed automatically and the scope-checked raw JS/source-map response bodies are retained under javascript/captured/ with javascript/captured-index.json (sensitive local evidence; source maps may embed source code). For additional source files, omit javascript_url and place an already-observed/captured file under the current target workspace's javascript/ directory, then run this tool. It recursively scans all regular .js/.mjs/.cjs and .map files there without following symlinks, parses source maps as data, and does not download or execute scripts. When javascript_url is supplied, source analysis is narrowed to that exact captured asset plus its directly referenced source maps, and ignores unrelated local files.",
    "Do not provide URL credentials, session tokens, or other secrets. This tool does not replace the existing scope enforcement.",
  ].join("\n"),
  parameters: CorrelateJavaScriptParameters,
  async execute(params, ctx) {
    try {
      const result = await JavaScriptCorrelation.build({
        sessionID: ctx.sessionID,
        targetURL: params.target_url,
        javascriptURL: params.javascript_url,
      })
      const graph = result.graph
      return {
        title: graph.sourceFiles.length || result.capturedAssetCount ? "JavaScript correlation saved" : "JavaScript correlation incomplete",
        output: [
          "Collection status: " + (result.capturedAssetCount > 0 ? "captured assets persisted" : "NO captured JavaScript/source-map response bodies found; this is not a successful collection"),
          "Persisted captured asset files: " + result.capturedAssetCount,
          "Analysis status: " + (graph.sourceFiles.length > 0 ? "source records analyzed" : "no source records analyzed"),
          "Target workspace: " + result.workspacePath,
          "Graph JSON: " + result.graphPath,
          "Endpoint candidates JSON: " + result.endpointPath,
          "Tester survey JSON: " + result.testerSurveyPath,
          "Saved note ID: " + result.noteID,
          "JavaScript asset URLs (including referenced maps): " + graph.javascriptAssets.length,
          "Local JavaScript/source-map records: " + graph.sourceFiles.length,
          "Source-map references: " + (graph.sourceMapReferences ?? []).length,
          "Source maps awaiting capture: " + (graph.sourceMapReferences ?? []).filter((item) => item.status === "referenced-not-captured").length,
          "Captured/local source-map records with incomplete content: " + graph.sourceFiles.filter((file) => Boolean(file.sourceMapURL && !file.sourceMapSource && ["no-sources-content", "partial-sources-content", "invalid-json", "unsupported", "truncated"].includes(file.sourceMapStatus ?? ""))).length,
          "Embedded source entries analyzed: " + graph.sourceFiles.filter((file) => Boolean(file.sourceMapSource)).length,
          ...(graph.sourceMapReferences ?? []).map((item) => "Source map " + item.url + " — " + item.status + " — " + item.note),
          "Function candidates: " + graph.javascriptAnalysis.functions.length,
          "Structured request candidates: " + graph.javascriptAnalysis.requestCandidates.length,
          "Secret-like assignments (fingerprints only; candidates only): " + graph.javascriptAnalysis.secretCandidates.length,
          "Role/feature hints: " + graph.javascriptAnalysis.roleHints.length,
          "Static JavaScript sink candidates (not confirmed findings): " + graph.javascriptAnalysis.riskSignals.length,
          "Static endpoint literals: " + graph.sourceFiles.reduce((sum, file) => sum + file.endpointLiterals.length, 0),
          "Unique endpoint candidates: " + graph.endpointCandidates.length,
          "Candidates overlapping captured traffic: " + graph.endpointCandidates.filter((endpoint) => endpoint.observedInTraffic).length,
          "Captured response evidence nodes: " + graph.evidence.length,
          "Related requests/responses: " + graph.requests.length,
          "Web functions: " + graph.webFunctions.length,
          "Request observations: " + graph.observations.length,
          "Potentially related findings: " + graph.findings.length,
          "Graph edges: " + graph.edges.length,
          ...graph.notes.map((note) => "- " + note),
        ].join("\n"),
        metadata: {
          graph_path: result.graphPath,
          endpoint_path: result.endpointPath,
          tester_survey_path: result.testerSurveyPath,
          endpoint_candidates: graph.endpointCandidates.length,
          observed_endpoint_candidates: graph.endpointCandidates.filter((endpoint) => endpoint.observedInTraffic).length,
          target_workspace: result.workspacePath,
          javascript_assets: graph.javascriptAssets.length,
          source_map_references: (graph.sourceMapReferences ?? []).length,
          source_maps_pending_capture: (graph.sourceMapReferences ?? []).filter((item) => item.status === "referenced-not-captured").length,
          source_maps_incomplete: graph.sourceFiles.filter((file) => Boolean(file.sourceMapURL && !file.sourceMapSource && ["no-sources-content", "partial-sources-content", "invalid-json", "unsupported", "truncated"].includes(file.sourceMapStatus ?? ""))).length,
          source_map_source_entries_analyzed: graph.sourceFiles.filter((file) => Boolean(file.sourceMapSource)).length,
          javascript_functions: graph.javascriptAnalysis.functions.length,
          javascript_request_candidates: graph.javascriptAnalysis.requestCandidates.length,
          javascript_secret_candidates: graph.javascriptAnalysis.secretCandidates.length,
          javascript_role_hints: graph.javascriptAnalysis.roleHints.length,
          javascript_risk_signals: graph.javascriptAnalysis.riskSignals.length,
          requests: graph.requests.length,
          web_functions: graph.webFunctions.length,
          observations: graph.observations.length,
          findings: graph.findings.length,
          edges: graph.edges.length,
          captured_asset_files: result.capturedAssetCount,
          collection_complete: result.capturedAssetCount > 0,
          analysis_complete: graph.sourceFiles.length > 0,
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
