---
name: attack-rag-vector-security
description: "Assess retrieval-augmented generation and vector-search systems for tenant isolation, retrieval authorization, prompt injection, poisoning, and data leakage."
category: "ai-security"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [rag, vector-database, embeddings, prompt-injection, tenant-isolation, ai-security]
tech_stack: [llm, embeddings, vector-search, retrieval, api]
chains_with: [llm-security, attack-mcp-security, attack-idor-automation, attack-information-disclosure, attack-triage-validation]
sources:
  - "https://genai.owasp.org/resource/owasp-top-10-for-large-language-model-applications-2025/"
  - "https://atlas.mitre.org/"
  - "https://owasp.org/www-project-api-security/"
---

# RAG and Vector Retrieval Security

## Objective
Verify that retrieval systems enforce authorization, provenance, and trust boundaries before retrieved content is placed into model context. The presence of confidential-sounding output is not proof unless the tester can connect it to a controlled source and a violated access policy.

## Test workflow
1. Inventory data sources, embedding pipelines, indexes, namespaces/collections, tenant keys, metadata filters, ingestion jobs, deletion/update paths, and the identity used for retrieval.
2. Create synthetic documents with unique harmless markers in controlled test tenants. Record the expected access matrix before asking questions.
3. Compare queries from two controlled identities. Confirm that authorization is applied server-side before context assembly, not only in the UI or prompt.
4. Check metadata-filter consistency across direct vector queries, semantic search, keyword/hybrid search, citations, summaries, exports, chat history, cached answers, and follow-up questions.
5. Test poisoned/retrieved instructions using inert text that asks the model to ignore task instructions or reveal a synthetic marker. Verify that retrieved data is treated as untrusted content and cannot grant tools/permissions or override authorization.
6. Review ingestion boundaries: external URLs, file parsing, document type handling, HTML/Markdown, metadata fields, chunk inheritance, provenance, re-indexing, and deletion propagation.
7. Check whether similarity scores, embeddings, IDs, namespace names, or citation URLs expose sensitive information across tenants. Use synthetic fixtures; do not attempt broad extraction or model inversion.
8. Validate downstream actions separately. A prompt injection that changes text is a lead; a security finding requires a controlled unauthorized read, tool action, policy bypass, or other material consequence.

## Safe test matrix
```text
Test A: principal A queries its synthetic marker -> expected visible
Test B: principal B queries the same known topic -> A's marker must remain unavailable
Test C: retrieved note contains inert adversarial instructions -> system policy and tool authorization remain unchanged
Test D: delete/update a synthetic document -> old chunks and cached answers cease to expose it according to documented consistency guarantees
```

## Impact chains
Useful chains include cross-tenant retrieval → confidential context enters another tenant's answer; poisoned document → tool-selection change → unauthorized tool action; deleted document remains indexed → stale confidential answer; citation URL → separately confirmed access-control defect. Prove each link with synthetic data and mark unverified links as hypotheses.

## False positives
- The answer is model-generated rather than retrieved from the controlled document.
- A citation points to a public document.
- Similarity between responses is mistaken for leakage.
- The metadata filter works in the retrieval layer even if the model mentions a related concept.
- A prompt injection attempt is ignored and no unauthorized action occurs.

## Output
Record model/version, index/namespace, principal, source document fingerprint, query, retrieved IDs/provenance, expected and observed policy, downstream action, sanitized evidence, impact and remediation. Never store private prompts or production document contents when a fingerprint and controlled marker are enough.


## Targeted quality-loop enrichment (2026-10-19)

### Retrieval authorization and provenance matrix
Use clearly labeled synthetic documents across two test users/tenants, with unique harmless markers in title and body. Test retrieval, citation, metadata filters, reranking, deletion, cache reuse, and conversation-memory boundaries while changing one principal/document boundary at a time. A model mentioning a marker does not automatically prove cross-tenant leakage unless the fixture was inaccessible by policy and retrieval context can be tied to the other tenant's record. Separate prompt injection from retrieval authorization and from unsafe tool actions. Chain to LLM security for instruction/tool-boundary behavior, property authorization for exposed metadata fields, and data-isolation review for cross-tenant retrieval; do not insert real confidential documents.


## Pipeline and lifecycle matrix

| Stage | Controlled review | Evidence to capture |
|---|---|---|
| Ingestion | Synthetic document enters through each supported connector | Source identity, parser, document fingerprint, metadata and tenant |
| Chunking | Compare parent ACL/tenant metadata with each derived chunk | Chunk-to-parent relation and inherited policy |
| Embedding/index | Confirm namespace/collection and metadata filters follow the source policy | Index ID, tenant tag, filter decision, retrieval principal |
| Retrieval/reranking | Compare semantic, keyword, hybrid, and fallback paths | Retrieved synthetic IDs before and after reranking |
| Context assembly | Verify only authorized chunks enter the model context | Redacted source IDs and authorization decision |
| Generation/citations | Confirm citations reference the retrieved source and preserve its access boundary | Citation ID/URL, source fingerprint, access policy |
| Cache/memory | Repeat with another controlled identity and a clean conversation | Cache key/context isolation and marker visibility |
| Update/deletion | Change or delete a synthetic source and follow documented consistency guarantees | Old/new version IDs, index cleanup, stale-result window |
| Tool handoff | Retrieved instructions request a harmless unrelated tool action | Whether server-side tool policy independently denies it |

## Data and tenant invariant

For each synthetic source, define a policy tuple: owner, tenant, readers, writers, source system, retention, and deletion semantics. Verify the tuple survives every transformation: document → chunks → embeddings/metadata → retrieved context → answer/citation → cache/history. A correct prompt is not a substitute for server-side retrieval filtering.

## Prompt-injection test discipline

Use harmless text that requests a synthetic marker or a benign tool action. The test should measure whether the system maintains policy and tool authorization, not whether it follows an instruction verbatim. Keep system prompts, production data, credentials, and real tool side effects out of fixtures. If the model refuses or safely ignores the text, record the control result; do not escalate by introducing real secrets or consequential actions.

## RAG evidence contract

Record ingestion_source, document_fingerprint, source_acl, tenant, chunk_ids, embedding/index version, filter_before_rerank, retrieved_ids, context_ids, citation_ids, cache_context, principal, synthetic_marker, expected_policy, observed_result, deletion_status, tool_authorization_result, and cleanup. Store IDs/fingerprints and minimal synthetic evidence, not production document contents or private prompts.

### Chain gates

- Cross-tenant chunk enters context → retrieval authorization/data isolation.
- Metadata is visible but source content remains inaccessible → field-level disclosure, not automatically document leakage.
- Poisoned text changes a tool proposal but server denies the tool call → resilience observation, not unauthorized action.
- Deleted source remains retrievable beyond documented consistency window → stale-index/deletion control gap with synthetic proof.
- Citation points to a separate publicly reachable resource → evaluate that resource independently; do not attribute its public access to RAG leakage.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use an owned RAG/LLM lab, application logs with secrets redacted, a repeatable prompt/response harness, and a vector-store console/CLI relevant to the deployment. Promptfoo or garak can support controlled LLM security evaluations.

### Installation and setup
- [Promptfoo installation and red teaming docs](https://www.promptfoo.dev/docs/installation/) — follow the official npm/npx workflow for a local evaluation project.
- [garak documentation](https://garak.ai/) — install and configure in an isolated test environment.
- [Docker installation](https://docs.docker.com/get-docker/) — useful for disposable local services where the project's platform supports it.
Review probes and output before running; configure test-only endpoints, synthetic documents, and limits. Never probe a third-party model or data store outside explicit program authorization.

### Primary resources
- [OWASP GenAI Security Project](https://genai.owasp.org/) — LLM application risk patterns.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) — trust, measurement, and governance.
- [MCP specification](https://modelcontextprotocol.io/specification) — when retrieval/actions cross a tool boundary.

### Reusable helper
`python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json` validates local evidence metadata; it does not connect to a model or vector database.

### Result handling
Use synthetic canaries and distinguish prompt injection, retrieval permission errors, cross-tenant retrieval, and ordinary relevance failures. Save only redacted prompts/results necessary to reproduce the issue.
