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
