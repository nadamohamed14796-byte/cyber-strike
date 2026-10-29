# Playbooks 总目录

> 每个 playbook 的视角都是黑盒——假定只有 URL 和参数，无源码

---

## 阅读建议

按“SRC 价值 / 易出货”顺序读：

| 优先级 | Playbook | 一句话价值 |
|-------|---------|-----------|
| 🔴 P0 | `unauth-access.md` | 默认凭据 / Redis-Mongo-ES / Actuator / Swagger / .git——开局送的 P0 |
| 🔴 P0 | `rce/00-index.md` | Log4Shell / Spring4Shell / Fastjson / Struts2 / 命令注入指纹库 |
| 🔴 P0 | `file-upload/00-index.md` | 解析漏洞 + 编辑器漏洞 + 截断绕过 |
| 🔴 P0 | `path-traversal/00-index.md` | 路径穿越 / LFI / RFI 及编码变体 |
| 🟠 P1 | `info-disclosure.md` | .git / .svn / 备份文件 / phpinfo / 日志 / OSS bucket |
| 🟠 P1 | `logic-flaws/00-index.md` | 密码重置 / IDOR / 越权 / 验证码 / 支付和工作流逻辑 |
| 🟠 P1 | `arbitrary-x-authz.md` | 任意 X 子授权、水平/垂直越权 |
| 🟠 P1 | `oauth-saml-jwt/00-index.md` | redirect_uri / state / JWT / SAML |
| 🟠 P1 | `sqli.md` | SQL 注入及高频参数线索 |
| 🟠 P1 | `ssrf-cache-host/00-index.md` | SSRF / 云元数据 / Host header / 缓存投毒 |
| 🟡 P1/P2 | `api-rest/00-index.md` | BOLA / Mass Assignment / 速率 / CORS / WebSocket |
| 🟡 P1/P2 | `graphql.md` | Introspection / 嵌套 IDOR / 查询复杂度 |
| 🟡 P2 | `race-conditions.md` | 竞态条件 / 重复权益 / 状态不一致 |
| 🟡 P2 | `xss/00-index.md` | XSS：反射、存储、DOM 与上下文分析 |
| 🟡 P2 | `http-smuggling.md` | CL.TE / TE.CL / HTTP 解析差异 |
| 🟡 P2 | `mobile.md` | Android / iOS / Intent / WebView |
| 🟡 P2 | `llm-prompt-injection/00-index.md` | Prompt injection / RAG / Agent tools |
| 🟡 P2 | `dos.md` | موارد واستهلاك غير محدود؛ اختبارات منخفضة التأثير فقط ووفق سياسة البرنامج |
| حسب التفويض | `intranet-postexp/00-index.md` | مراجع الشبكات الداخلية وما بعد الاستغلال؛ لا تُستخدم إلا بتفويض صريح للأصول والتقنيات المعنية |

---

## كل playbook يحتوي على

1. تعريف النوع ولماذا يهم في برامج SRC.
2. نقاط دخول ومعلمات وإشارات تستحق الفحص.
3. أسلوب اختبار وإشارات استجابة تساعد على التحقق.
4. اختلافات آمنة ومسموح بها عند وجود سبب واضح.
5. شروط مسبقة وحدود الأثر المحتمل.
6. أمثلة تاريخية أو بصمات مرجعية عند توافرها.
7. متطلبات حفظ الأدلة وخطوات إعادة الإنتاج.
8. حدود الاختبار والتوقف والتنظيف.

---

## علاقته بالمراجع الأخرى

```
methodology/01-attack-priority   → اختيار فرضية الاختبار التالية
methodology/04-control-gap       → ربط الميزة بإشارة التحكم الناقص
methodology/02-bypass-toolkit    → تنويعات محدودة عند وجود سبب واختبار مسموح
methodology/03-evidence          → مراجعة الأدلة قبل التقرير
playbooks/<type>.md              → خطوات النوع المحدد
../payloader/SKILL.md            → عند الحاجة إلى فئة payload محددة؛ تُحمّل الفئة المطلوبة فقط
../h1-reports/by-weakness/SKILL.md → عند الحاجة إلى مثال تاريخي مشابه؛ يُقرأ ملف الضعف المطابق فقط
../templates/report-submission.md → قالب التقرير
```

المراجع المساندة ليست إذنًا للاختبار ولا دليلًا على وجود ثغرة في الهدف الحالي. تُستخدم فقط عندما تدعمها أدلة الهدف، وتبقى حدود النطاق وسياسة البرنامج هي المرجع الحاكم.
