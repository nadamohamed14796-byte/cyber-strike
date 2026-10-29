---
name: src-hunter-payloader-tools
description: On-demand index for src-hunter tool/command references. Load only when a specific authorized web-testing workflow needs a tool syntax reference.
category: security-tools
tags: [tools, commands, web-testing, recon, encoding, vulnerability-validation]
---

# Tool reference routing

For web bug bounty work, the usual relevant file is `web渗透.md`. Other tool references are not automatically needed. Use this skill's returned **Base directory for this skill** and `<skill_files>` list to read the exact runtime path for one file at a time. Verify the tool is installed, its flags are understood, and its use fits the target's scope and impact limits.

- Web testing: `web渗透.md`
- Recon: `信息收集.md`
- Encoding/decoding: `编码解码.md`
- Exploitation reference: `漏洞利用.md` (reference only; avoid destructive/exfiltration actions)
- System commands: `系统命令.md` (read-only/minimum-impact only)
- Password attacks: `密码攻击.md` (do not spray/credential-stuff)
- Credential theft: `凭证窃取.md` (do not execute)
- Reverse shells: `反弹shell.md` (not for ordinary bug bounty validation)
- Internal network / Windows / domain / privilege escalation / red-team tools / tunneling: only for explicitly authorized internal assessments; never infer authorization from these references.

A listed command is not automatically safe, installed, permitted, or appropriate. Do not execute command lists wholesale.
