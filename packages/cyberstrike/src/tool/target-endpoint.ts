import z from "zod"
import { Session } from "../session"
import { TargetMemory } from "../target"
import { Tool } from "./tool"

const EvidenceSource = z.enum(["javascript", "traffic", "contract", "crawl", "active-test", "other"])
const Confidence = z.enum(["candidate", "observed", "confirmed", "refuted", "inconclusive", "blocked"])

const EvidenceInput = z.object({
  source: EvidenceSource,
  path_parameters: z.array(z.string().min(1)).optional(),
  query_parameters: z.array(z.string().min(1)).optional(),
  body_parameters: z.array(z.string().min(1)).optional(),
  header_names: z.array(z.string().min(1)).optional(),
  auth_signals: z.array(z.string().min(1)).optional(),
  cookie_signals: z.array(z.string().min(1)).optional(),
  content_types: z.array(z.string().min(1)).optional(),
  source_files: z.array(z.string().min(1)).optional(),
  request_ids: z.array(z.string().min(1)).optional(),
  confidence: Confidence.optional(),
})

const OperationInput = z.object({
  method: z.string().trim().min(1).regex(/^[!#$%&'*+.^_\x60|~0-9A-Z-]+$/i).describe("HTTP method token for this operation, such as GET or POST. Do not combine multiple methods into one operation."),
  method_evidence_sources: z.array(EvidenceSource).optional(),
  path_parameters: z.array(z.string().min(1)).optional(),
  query_parameters: z.array(z.string().min(1)).optional(),
  body_parameters: z.array(z.string().min(1)).optional(),
  header_names: z.array(z.string().min(1)).optional(),
  auth_signals: z.array(z.string().min(1)).optional(),
  cookie_signals: z.array(z.string().min(1)).optional(),
  content_types: z.array(z.string().min(1)).optional(),
  source_files: z.array(z.string().min(1)).optional(),
  request_ids: z.array(z.string().min(1)).optional(),
  observed_in_traffic: z.boolean().optional(),
  confidence: Confidence.optional(),
  evidence: z.array(EvidenceInput).optional(),
})

const EndpointEvidenceFields = z.object({
  path_parameters: z.array(z.string().min(1)).optional(),
  query_parameters: z.array(z.string().min(1)).optional(),
  body_parameters: z.array(z.string().min(1)).optional(),
  header_names: z.array(z.string().min(1)).optional(),
  auth_signals: z.array(z.string().min(1)).optional(),
  cookie_signals: z.array(z.string().min(1)).optional(),
  content_types: z.array(z.string().min(1)).optional(),
  source_files: z.array(z.string().min(1)).optional(),
  request_ids: z.array(z.string().min(1)).optional(),
})

const Parameters = z.object({
  target_url: z.string().min(1).describe("Existing canonical target workspace URL; must already be observed and in scope in this session."),
  origin: z.string().url().nullable().describe("Exact endpoint origin, including scheme and non-default port. Use null only when the origin genuinely cannot be established."),
  path: z.string().min(1).refine((value) => value.startsWith("/"), "Endpoint path must be an absolute URL path."),
  source_files: z.array(z.string().min(1)).optional(),
  operations: z.array(OperationInput).min(1).describe("One object per HTTP method. Keep each method's fields in its own operation."),
  unattributed: EndpointEvidenceFields.optional().describe("Route-level evidence for which no specific HTTP method is known. Never copy this data into every operation."),
})

const toEvidence = (value: z.infer<typeof EvidenceInput>) => ({
  source: value.source,
  pathParameters: value.path_parameters,
  queryParameters: value.query_parameters,
  bodyParameters: value.body_parameters,
  headerNames: value.header_names,
  authSignals: value.auth_signals,
  cookieSignals: value.cookie_signals,
  contentTypes: value.content_types,
  sourceFiles: value.source_files,
  requestIDs: value.request_ids,
  confidence: value.confidence,
})

export const TargetEndpointTool = Tool.define<typeof Parameters, Tool.Metadata>("target_endpoint", {
  description: [
    "Merge endpoint and HTTP-operation intelligence into one canonical endpoint record in the existing target workspace. This is the required write path for any Agent discovering or enriching an API endpoint.",
    "Endpoint identity is normalized origin + route template + API version (normally encoded in the path). HTTP methods are nested operations, not separate endpoint notes. Send one operation object per method and keep that method's parameters, headers, auth/cookie clues, Content-Type, source files, request IDs, and confidence inside it.",
    "Use evidence[] when the same operation has multiple sources. Each evidence item identifies its source (javascript, traffic, contract, crawl, active-test, or other) and carries only the fields supported by that source. Never label a traffic-only method as JavaScript-declared. Keep route-level clues with unknown method in unattributed; do not copy them to all methods.",
    "This tool merges incrementally and is idempotent: new fields enrich the existing endpoint/operation; duplicates do not create another note. The original requests and responses remain in the canonical request store; pass request_ids as references and never copy raw tokens, cookies, authorization values, or request bodies into endpoint evidence.",
    "The target workspace must already exist and be observed in this session. This tool only records evidence; it does not test the endpoint or confirm a vulnerability.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params, ctx) {
    try {
      const sessionID = Session.root(ctx.sessionID)
      const requestedTarget = params.target_url
      let workspace = await TargetMemory.get(requestedTarget)
      const observedRequestedTarget = TargetMemory.isObservedInSession(sessionID, requestedTarget)
      if (!workspace && observedRequestedTarget) {
        try {
          const decision = await TargetMemory.checkURLScope(requestedTarget)
          if (decision.allowed && decision.workspace) workspace = decision.workspace
        } catch {
          // Keep the safe failure below when scope cannot be established.
        }
      }
      if (!workspace) {
        return {
          title: "Canonical endpoint not saved",
          output: "No existing workspace matches this target, and no observed in-scope workspace could be resolved.",
          metadata: { saved: false, reason: "workspace_missing" },
        }
      }
      if (!observedRequestedTarget && !TargetMemory.isObservedInSession(sessionID, workspace.targetURL)) {
        return {
          title: "Canonical endpoint not saved",
          output: "The requested target and its canonical workspace were not observed in this session tree's requests or Intel. No endpoint record was written.",
          metadata: { saved: false, reason: "target_not_observed" },
        }
      }

      const endpointURL = new URL(params.path, params.origin ?? workspace.targetURL)
      const endpointScope = await TargetMemory.checkURLScope(endpointURL.href)
      if (!endpointScope.allowed || !endpointScope.workspace) {
        return {
          title: "Canonical endpoint not saved",
          output: "The endpoint origin/path is outside the persisted scope or has no matching canonical workspace. No endpoint record was written. Reason: " + endpointScope.reason,
          metadata: { saved: false, reason: endpointScope.reason ?? "endpoint_out_of_scope" },
        }
      }
      workspace = endpointScope.workspace

      const saved = await TargetMemory.mergeCanonicalEndpointRecord({
        targetURL: workspace.targetURL,
        origin: params.origin,
        path: params.path,
        sourceFiles: params.source_files,
        operations: params.operations.map((operation) => ({
          method: operation.method,
          methodEvidenceSources: operation.method_evidence_sources,
          pathParameters: operation.path_parameters,
          queryParameters: operation.query_parameters,
          bodyParameters: operation.body_parameters,
          headerNames: operation.header_names,
          authSignals: operation.auth_signals,
          cookieSignals: operation.cookie_signals,
          contentTypes: operation.content_types,
          sourceFiles: operation.source_files,
          requestIDs: operation.request_ids,
          observedInTraffic: operation.observed_in_traffic,
          confidence: operation.confidence,
          evidence: operation.evidence?.map(toEvidence),
        })),
        unattributed: params.unattributed ? {
          pathParameters: params.unattributed.path_parameters,
          queryParameters: params.unattributed.query_parameters,
          bodyParameters: params.unattributed.body_parameters,
          headerNames: params.unattributed.header_names,
          authSignals: params.unattributed.auth_signals,
          cookieSignals: params.unattributed.cookie_signals,
          contentTypes: params.unattributed.content_types,
          sourceFiles: params.unattributed.source_files,
          requestIDs: params.unattributed.request_ids,
        } : undefined,
      })

      const action = saved.created ? "created" : saved.updated ? "updated" : "already current"
      return {
        title: "Canonical endpoint " + action,
        output: [
          "Target: " + saved.workspace.targetURL,
          "Endpoint: " + (params.origin ?? "(origin unresolved)") + params.path,
          "Endpoint ID: " + (saved.note.content.match(/- Identity: (.+)/)?.[1] ?? "stored"),
          "Operations: " + params.operations.map((item) => item.method.trim().toUpperCase()).join(", "),
          "Record: " + action,
          "Note ID: " + saved.note.id,
          "Workspace: " + saved.workspace.workspacePath,
          "Raw requests and responses remain in the canonical request store.",
        ].join("\n"),
        metadata: {
          saved: saved.created || saved.updated,
          created: saved.created,
          updated: saved.updated,
          note_id: saved.note.id,
          target_id: saved.workspace.id,
          workspace: saved.workspace.workspacePath,
        },
      }
    } catch (error) {
      return {
        title: "Canonical endpoint merge failed",
        output: error instanceof Error ? error.message : String(error),
        metadata: { saved: false, error: true },
      }
    }
  },
})
