---
name: attack-llm-security
description: "Assess authorized LLM applications for prompt injection, unsafe tool use, and data-boundary failures"
category: "ai-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [llm, prompt-injection, data-leakage, tool-use, ai-security]
tech_stack: [llm, rag, web, api]
prerequisites:
  - "Written authorization and a dedicated test workspace"
  - "Synthetic data and a clear list of allowed model/tool actions"
chains_with: [attack-mcp-security, attack-api-misconfig, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-llm-ai/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/llm-prompt-injection/SKILL.md"
---

# LLM Application Security Assessment

## When to use

Use when an application uses an LLM to process user input, retrieve documents, invoke tools, summarize private content, or make decisions that affect users or external systems.

## Safety gate

Use only a designated test workspace with synthetic documents and non-sensitive tool actions. Do not attempt to extract real system prompts, credentials, private training data, or other users' records. Never let test prompts trigger real external side effects.

## Procedure

1. Map user input, system/developer instructions, retrieval sources, tool calls, memory, and output sinks.
2. Identify security boundaries: tenant data, access-controlled documents, tool permissions, moderation policy, and output consumers.
3. Create benign canary documents with unique markers and explicit access labels to test retrieval and isolation.
4. Test whether untrusted retrieved content can change the model's behavior, cross the instruction/data boundary, or induce an unauthorized tool call.
5. Test direct and indirect prompt injection separately. Use harmless instructions that attempt to reveal only synthetic canaries or request a mock action.
6. Verify server-side authorization independently of model reasoning. The model must not be the sole gate protecting data or actions.
7. Check output handling for HTML/script injection, unsafe SQL/command construction, or downstream automation. Validate only in a sandbox.
8. Record reproducible inputs, retrieval context, tool invocation traces, expected policy, and observed effect. Repeat with controls to rule out nondeterministic output.
9. Assess impact narrowly: unauthorized disclosure, cross-tenant retrieval, tool misuse, or unsafe output handling.

## Pitfalls

- A model producing disallowed text is not automatically a security impact.
- Prompt injection is a technique; the report must identify which protected boundary failed.
- Do not use real secrets or real user documents to demonstrate leakage.
- Model non-determinism requires careful controls and repeatable evidence.

## Verification

A confirmed issue needs a repeatable failure of a defined security boundary using synthetic data or an approved sandbox action. State model/provider only when known, and distinguish observed behavior from inferred impact.
