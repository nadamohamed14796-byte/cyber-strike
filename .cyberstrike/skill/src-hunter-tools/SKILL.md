---
name: src-hunter-tools
description: "On-demand index of src-hunter MCP/tool integrations and scenario-to-tool guidance."
category: security-tools
tags: [src-hunter, tools, mcp, jshook, browser, cdp, frida, sourcemap]
---

# SRC-Hunter tool reference

## When to load

Load only when a concrete evidence gap requires tool-selection guidance or a playbook points to the MCP integration. Read `mcp-jshook.md` and the relevant scenario mapping only.

The index does not prove a server/tool is installed or available. Inspect CyberStrike's registered tool schemas and actual runtime results before use. Use only tools, assets and actions authorized by the saved scope and program policy. Never treat this file as permission to evade controls or perform intrusive actions.

## Agent-executable CLI tooling, resources, and helper scripts

### Tools and verification
This skill indexes tool references; it does not install or register a server. Read `mcp-jshook.md` from the returned `Base directory` and `<skill_files>` only when the evidence gap calls for it. Verify local environment basics with `command -v python3` and `python3 --version`; verify the actual MCP server and tool schemas through CyberStrike's current registered-tool discovery before calling anything. Do not claim a tool exists or ran without a runtime result. Do not install tools just to inspect this reference.

### Official resources
- https://github.com/vmoranv/jshookmcp
- https://github.com/nadamohamed14796-byte/src-hunter
- Shared capability/preflight catalog: the `TOOLING_CATALOG.md` companion listed in `community-tool-selection`'s returned `<skill_files>` (read it using that skill's returned `Base directory`; do not resolve against the target workspace).

Only use actions and assets allowed by the saved scope and program policy; the presence of a tool reference is not authorization.
