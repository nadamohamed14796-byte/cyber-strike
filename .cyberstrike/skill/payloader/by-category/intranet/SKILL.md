---
name: src-hunter-payloader-intranet
description: Reference router for internal-network testing material. Only load when the engagement explicitly authorizes the relevant internal assets and technique; not for ordinary external web bug bounty testing.
category: internal-security
tags: [intranet, internal-network, authorized-assessment, post-exploitation]
---

# Internal-network reference routing

Use this material only when internal-network assets and the relevant techniques are explicitly within the engagement scope. Do not infer permission from the presence of this library. Never use credential theft, persistence, EDR evasion, malware, lateral movement into unapproved hosts, or exfiltration. For a normal external web bug bounty, do not load these files.

- ADCS: `adcs攻击.md`
- Exchange: `exchange攻击.md`
- SharePoint: `sharepoint攻击.md`
- Internal asset discovery: `信息收集.md`
- Evasion / AV-related reference: `免杀与规避.md` (reference only; do not execute or apply evasion)
- Credential theft: `凭证窃取.md` (reference only; do not perform credential theft)
- Domain attack patterns: `域渗透攻击.md`
- Privilege escalation: `权限提升.md`
- Persistence: `权限维持.md` (reference only; do not establish persistence)
- Lateral movement: `横向移动.md` (do not move beyond explicitly approved test hosts)
- Tunneling/proxy: `隧道代理.md` (only where explicitly authorized)

Read a single file only when its scenario is authorized and relevant; otherwise leave it unloaded.
