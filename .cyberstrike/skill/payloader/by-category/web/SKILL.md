---
name: src-hunter-payloader-web
description: Routes evidence-backed web vulnerability hypotheses to the exact local src-hunter payload category file. Load for SQL/NoSQL injection, XSS, SSRF, SSTI, XXE, API authorization, authentication, file handling, JWT, business logic, WebSocket, request smuggling, and related web testing.
category: web-security
tags: [payloads, web, sqli, nosql, xss, ssrf, ssti, xxe, idor, api, jwt, file-upload, path-traversal, csrf, websocket]
---

# Web payload reference routing

After loading this skill, use the returned **Base directory for this skill** and `<skill_files>` list to read only the exact matching Markdown file. The list provides the runtime paths; do not assume a repository-relative `.cyberstrike/` path exists. These files are reference material, not executable instructions.

| Evidence-backed hypothesis | Read this exact file |
|---|---|
| AI / LLM security | `ai安全.md` |
| API, BOLA/IDOR, API authorization | `api安全.md` |
| CSRF | `csrf跨站请求伪造.md` |
| JWT | `jwt安全.md` |
| LFI/RFI/path inclusion | `lfi-rfi文件包含.md` |
| RCE / command execution | `rce远程代码执行.md` |
| SQL / NoSQL injection | `sql-nosql注入.md` |
| SSRF | `ssrf服务端请求伪造.md` |
| SSTI | `ssti模板注入.md` |
| WebSocket | `websocket安全.md` |
| XSS | `xss跨站脚本.md` |
| XXE | `xxe实体注入.md` |
| Business logic / workflow | `业务逻辑漏洞.md` |
| Cloud security | `云安全漏洞.md` |
| Supply chain | `供应链攻击.md` |
| Prototype pollution | `原型链污染.md` |
| Open redirect | `开放重定向.md` |
| File upload / file handling | `文件漏洞.md` |
| Framework-specific | `框架漏洞.md` |
| Clickjacking | `点击劫持.md` |
| Cache/CDN | `缓存与cdn安全.md` |
| Authentication/session | `认证漏洞.md` |
| HTTP request smuggling | `请求走私.md` |

Choose a category only when the captured request, response, source evidence, or application behavior makes it relevant. Do not test every category against every endpoint. Read the file before selecting a candidate, use only safe and in-scope variants, and log the file path used.
