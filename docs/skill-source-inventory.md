# External Skill Source Inventory

Generated from the Git trees of the two requested source repositories and the CyberStrike feature branch.

## Counts

- Claude-BugHunter source skills: 83.
- recon-skills source skills: 146.
- Current CyberStrike top-level curated skill directories on this branch: 82 (after the fourth adapted batch).
- This is a staged migration inventory. The current branch includes an initial batch and a second batch of 12 adapted skills; it does not mean all upstream skills have been imported.

## Mapping rules

- Candidate mappings are name-based aliases to help review, not proof of semantic equivalence.
- A target candidate marked present must still be compared with the source before deciding whether to merge, expand, or keep separate.
- A missing candidate is not an instruction to copy blindly; assess overlap, license, safety, runtime support, and usefulness first.
- Repositories contain repeated skill names across categories; repeated source rows are intentionally retained so provenance is not lost.

| Source repository | Source skill path | Candidate CyberStrike skill | Status |
|---|---|---|---|
| Claude-BugHunter | `skills/apk-redteam-pipeline/SKILL.md` | `attack-apk-redteam-pipeline` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/bb-local-toolkit/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/bb-methodology/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/bug-bounty/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/bugcrowd-reporting/SKILL.md` | `attack-bugcrowd-reporting` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/cloud-iam-deep/SKILL.md` | `attack-cloud-iam-deep` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/enterprise-vpn-attack/SKILL.md` | `attack-enterprise-vpn-attack` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/evidence-hygiene/SKILL.md` | `attack-evidence-hygiene` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-api-misconfig/SKILL.md` | `attack-api-misconfig` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-aspnet/SKILL.md` | `attack-aspnet` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-ato/SKILL.md` | `attack-ato` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-auth-bypass/SKILL.md` | `attack-auth-bypass` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-brute-force/SKILL.md` | `attack-brute-force` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-business-logic/SKILL.md` | `attack-business-logic` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-cache-poison/SKILL.md` | `attack-cache-poison` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-captcha-bypass/SKILL.md` | `attack-captcha-bypass` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-cicd/SKILL.md` | `cicd-attacks` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-clickjacking/SKILL.md` | `attack-clickjacking` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-cloud-misconfig/SKILL.md` | `cloud-assessment` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-cors/SKILL.md` | `attack-cors` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-csrf/SKILL.md` | `attack-csrf` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-deserialization/SKILL.md` | `attack-deserialization` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-dispatch/SKILL.md` | `attack-dispatch` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-dom/SKILL.md` | `attack-dom` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-exceptional-conditions/SKILL.md` | `attack-exceptional-conditions` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-file-upload/SKILL.md` | `attack-file-upload` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-fintech-graphql/SKILL.md` | `attack-fintech-graphql` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-forgot-password/SKILL.md` | `attack-password-reset` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-graphql/SKILL.md` | `attack-graphql` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-grpc/SKILL.md` | `attack-grpc` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-host-header/SKILL.md` | `attack-host-header` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-html-injection/SKILL.md` | `attack-html-injection` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-http-smuggling/SKILL.md` | `attack-request-smuggling` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-idor/SKILL.md` | `attack-idor-automation` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-jwt-crypto/SKILL.md` | `attack-jwt` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-k8s/SKILL.md` | `k8s-assessment` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-laravel/SKILL.md` | `attack-laravel` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-ldap/SKILL.md` | `attack-ldap` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-lfi/SKILL.md` | `attack-lfi` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-llm-ai/SKILL.md` | `attack-llm-ai` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-mfa-bypass/SKILL.md` | `attack-mfa-bypass` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-misc/SKILL.md` | `attack-misc` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-nextjs/SKILL.md` | `attack-nextjs` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-nodejs/SKILL.md` | `attack-nodejs` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-nosqli/SKILL.md` | `attack-nosqli` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-ntlm-info/SKILL.md` | `attack-ntlm-info` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-oauth/SKILL.md` | `attack-oauth` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-open-redirect/SKILL.md` | `attack-open-redirect` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-race-condition/SKILL.md` | `attack-race-condition` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-rag-vector/SKILL.md` | `attack-rag-vector` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-rce/SKILL.md` | `attack-rce` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-saml/SKILL.md` | `attack-saml` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-session/SKILL.md` | `attack-session` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-shadow-api/SKILL.md` | `attack-shadow-api` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-sharepoint/SKILL.md` | `attack-sharepoint` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-source-leak/SKILL.md` | `attack-source-leak` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-spa-api/SKILL.md` | `attack-spa-api` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-springboot/SKILL.md` | `attack-springboot` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-sqli/SKILL.md` | `attack-sqli` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-ssrf/SKILL.md` | `attack-ssrf` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-ssti/SKILL.md` | `attack-ssti` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-subdomain/SKILL.md` | `attack-subdomain-takeover` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-tls-network/SKILL.md` | `attack-tls-network` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/hunt-websocket/SKILL.md` | `attack-websocket` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-xss/SKILL.md` | `attack-xss` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/hunt-xxe/SKILL.md` | `attack-xxe` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/ios-redteam-pipeline/SKILL.md` | `attack-ios-redteam-pipeline` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/m365-entra-attack/SKILL.md` | `attack-m365-entra-attack` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/meme-coin-audit/SKILL.md` | `attack-meme-coin-audit` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/mid-engagement-ir-detection/SKILL.md` | `attack-mid-engagement-ir-detection` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/offensive-osint/SKILL.md` | `attack-offensive-osint` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/okta-attack/SKILL.md` | `attack-okta-attack` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/osint-methodology/SKILL.md` | `attack-osint-methodology` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/recon-scope-triage/SKILL.md` | `attack-recon-scope-triage` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/redteam-mindset/SKILL.md` | `attack-redteam-mindset` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/redteam-report-template/SKILL.md` | `attack-redteam-report-template` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/report-writing/SKILL.md` | `attack-report-writing` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/security-arsenal/SKILL.md` | `attack-security-arsenal` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/supply-chain-attack-recon/SKILL.md` | `attack-supply-chain-attack-recon` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/triage-validation/SKILL.md` | `attack-triage-validation` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/vmware-vcenter-attack/SKILL.md` | `attack-vmware-vcenter-attack` | not mapped — review for new skill or merge |
| Claude-BugHunter | `skills/web2-recon/SKILL.md` | `attack-web-recon` | candidate exists — semantic merge/review required |
| Claude-BugHunter | `skills/web3-audit/SKILL.md` | `attack-web3-audit` | not mapped — review for new skill or merge |
| recon-skills | `auth/saml-sso-attack/SKILL.md` | `attack-saml` | candidate exists — semantic merge/review required |
| recon-skills | `chains/cross-attack-chains/SKILL.md` | `attack-cross-attack-chains` | not mapped — review for new skill or merge |
| recon-skills | `chains/wordpress-full-compromise/SKILL.md` | `attack-wordpress-full-compromise` | not mapped — review for new skill or merge |
| recon-skills | `infra/docker-privesc/SKILL.md` | `attack-docker-privesc` | not mapped — review for new skill or merge |
| recon-skills | `meta/attack-patterns-reference/SKILL.md` | `attack-attack-patterns-reference` | not mapped — review for new skill or merge |
| recon-skills | `meta/cross-wave-delta-analysis/SKILL.md` | `attack-cross-wave-delta-analysis` | not mapped — review for new skill or merge |
| recon-skills | `meta/google-dorks-catalog/SKILL.md` | `attack-google-dorks-catalog` | not mapped — review for new skill or merge |
| recon-skills | `meta/pentest-playbook/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| recon-skills | `meta/recon-playbook/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| recon-skills | `meta/sector-recon-methodology/SKILL.md` | `attack-sector-recon-methodology` | not mapped — review for new skill or merge |
| recon-skills | `recon/401-403-bypass/SKILL.md` | `attack-401-403-bypass` | not mapped — review for new skill or merge |
| recon-skills | `recon/api-noauth-hunt/SKILL.md` | `attack-web-recon` | candidate exists — semantic merge/review required |
| recon-skills | `recon/asn-infrastructure-mapping/SKILL.md` | `attack-asn-infrastructure-mapping` | not mapped — review for new skill or merge |
| recon-skills | `recon/cache-attack/SKILL.md` | `attack-cache-attack` | not mapped — review for new skill or merge |
| recon-skills | `recon/cms-detection/SKILL.md` | `attack-cms-detection` | not mapped — review for new skill or merge |
| recon-skills | `recon/cors-credential-wordpress/SKILL.md` | `attack-cors-credential-wordpress` | not mapped — review for new skill or merge |
| recon-skills | `recon/deep-invade/SKILL.md` | `attack-web-recon` | candidate exists — semantic merge/review required |
| recon-skills | `recon/email-security/SKILL.md` | `attack-email-security` | not mapped — review for new skill or merge |
| recon-skills | `recon/error-log-mining/SKILL.md` | `attack-error-log-mining` | not mapped — review for new skill or merge |
| recon-skills | `recon/exchange-owa-attack/SKILL.md` | `attack-exchange-owa-attack` | not mapped — review for new skill or merge |
| recon-skills | `recon/firebase-supabase-attack/SKILL.md` | `attack-firebase-supabase-attack` | not mapped — review for new skill or merge |
| recon-skills | `recon/flask-werkzeug-attack/SKILL.md` | `attack-flask-werkzeug-attack` | not mapped — review for new skill or merge |
| recon-skills | `recon/github-secret-hunting/SKILL.md` | `attack-github-secret-hunting` | not mapped — review for new skill or merge |
| recon-skills | `recon/gitlab-public-recon/SKILL.md` | `attack-gitlab-public-recon` | not mapped — review for new skill or merge |
| recon-skills | `recon/hardcoded-credential-hunt/SKILL.md` | `attack-hardcoded-credential-hunt` | not mapped — review for new skill or merge |
| recon-skills | `recon/http2-header-impersonation/SKILL.md` | `attack-http2-header-impersonation` | not mapped — review for new skill or merge |
| recon-skills | `recon/humanize-automation/SKILL.md` | `attack-humanize-automation` | not mapped — review for new skill or merge |
| recon-skills | `recon/iot-camera-recon/SKILL.md` | `attack-iot-camera-recon` | not mapped — review for new skill or merge |
| recon-skills | `recon/js-secrets-extraction/SKILL.md` | `attack-js-secrets-extraction` | candidate exists — semantic merge/review required |
| recon-skills | `recon/jwt-attack/SKILL.md` | `attack-jwt-attack` | not mapped — review for new skill or merge |
| recon-skills | `recon/origin-ip-discovery/SKILL.md` | `attack-origin-ip-discovery` | not mapped — review for new skill or merge |
| recon-skills | `recon/phpinfo-to-rce/SKILL.md` | `attack-phpinfo-to-rce` | not mapped — review for new skill or merge |
| recon-skills | `recon/port-mass-scan/SKILL.md` | `attack-port-mass-scan` | not mapped — review for new skill or merge |
| recon-skills | `recon/port-service-discovery/SKILL.md` | `attack-port-service-discovery` | candidate exists — semantic merge/review required |
| recon-skills | `recon/s3-minio-content-type-xss/SKILL.md` | `attack-s3-minio-content-type-xss` | not mapped — review for new skill or merge |
| recon-skills | `recon/scada-hikvision-isapi/SKILL.md` | `attack-scada-hikvision-isapi` | not mapped — review for new skill or merge |
| recon-skills | `recon/source-leak-hunt/SKILL.md` | `attack-source-leak-hunt` | not mapped — review for new skill or merge |
| recon-skills | `recon/staging-subdomain-hunt/SKILL.md` | `attack-staging-subdomain-hunt` | not mapped — review for new skill or merge |
| recon-skills | `recon/stealth-browser-launch/SKILL.md` | `attack-stealth-browser-launch` | not mapped — review for new skill or merge |
| recon-skills | `recon/subdomain-enumeration/SKILL.md` | `attack-subdomain-enumeration` | candidate exists — semantic merge/review required |
| recon-skills | `recon/subdomain-takeover-hunt/SKILL.md` | `attack-subdomain-takeover-hunt` | not mapped — review for new skill or merge |
| recon-skills | `recon/tls-fingerprint-impersonation/SKILL.md` | `attack-tls-fingerprint-impersonation` | not mapped — review for new skill or merge |
| recon-skills | `recon/unauth-api-flow-hijack/SKILL.md` | `attack-unauth-api-flow-hijack` | not mapped — review for new skill or merge |
| recon-skills | `recon/vhost-enumeration/SKILL.md` | `attack-vhost-enumeration` | not mapped — review for new skill or merge |
| recon-skills | `recon/visual-recon/SKILL.md` | `attack-visual-recon` | not mapped — review for new skill or merge |
| recon-skills | `recon/web-enumeration/SKILL.md` | `attack-web-enumeration` | candidate exists — semantic merge/review required |
| recon-skills | `recon/wordpress-plugin-hunt/SKILL.md` | `attack-wordpress-plugin-hunt` | not mapped — review for new skill or merge |
| recon-skills | `recon/wp-mass-recon/SKILL.md` | `attack-wp-mass-recon` | not mapped — review for new skill or merge |
| recon-skills | `recon/wp-plugin-rest-auth-bypass/SKILL.md` | `attack-wp-plugin-rest-auth-bypass` | not mapped — review for new skill or merge |
| recon-skills | `recon/xmlrpc-exploitation/SKILL.md` | `attack-xmlrpc-exploitation` | not mapped — review for new skill or merge |
| recon-skills | `recon/zimbra-attack/SKILL.md` | `attack-zimbra-attack` | not mapped — review for new skill or merge |
| recon-skills | `redteam/apk-redteam-pipeline/SKILL.md` | `attack-apk-redteam-pipeline` | not mapped — review for new skill or merge |
| recon-skills | `redteam/bb-local-toolkit/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/bb-methodology/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/bug-bounty/SKILL.md` | `attack-bb-methodology` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/bugcrowd-reporting/SKILL.md` | `attack-bugcrowd-reporting` | not mapped — review for new skill or merge |
| recon-skills | `redteam/cloud-iam-deep/SKILL.md` | `attack-cloud-iam-deep` | not mapped — review for new skill or merge |
| recon-skills | `redteam/cors-chain-automation/SKILL.md` | `attack-cors-chain-automation` | not mapped — review for new skill or merge |
| recon-skills | `redteam/enterprise-vpn-attack/SKILL.md` | `attack-enterprise-vpn-attack` | not mapped — review for new skill or merge |
| recon-skills | `redteam/evidence-hygiene/SKILL.md` | `attack-evidence-hygiene` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-api-misconfig/SKILL.md` | `attack-api-misconfig` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-aspnet/SKILL.md` | `attack-aspnet` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-ato/SKILL.md` | `attack-ato` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-auth-bypass/SKILL.md` | `attack-auth-bypass` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-broken-function-level-auth/SKILL.md` | `attack-broken-function-level-auth` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-brute-force/SKILL.md` | `attack-brute-force` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-business-logic/SKILL.md` | `attack-business-logic` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-cache-poison/SKILL.md` | `attack-cache-poison` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-cicd/SKILL.md` | `cicd-attacks` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-cloud-misconfig/SKILL.md` | `cloud-assessment` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-cors/SKILL.md` | `attack-cors` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-csrf/SKILL.md` | `attack-csrf` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-deserialization/SKILL.md` | `attack-deserialization` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-dispatch/SKILL.md` | `attack-dispatch` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-django/SKILL.md` | `attack-django` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-dom/SKILL.md` | `attack-dom` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-fastapi/SKILL.md` | `attack-fastapi` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-file-upload/SKILL.md` | `attack-file-upload` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-firebase/SKILL.md` | `attack-firebase` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-graphql/SKILL.md` | `attack-graphql` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-grpc/SKILL.md` | `attack-grpc` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-host-header/SKILL.md` | `attack-host-header` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-http-smuggling/SKILL.md` | `attack-request-smuggling` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-idor/SKILL.md` | `attack-idor-automation` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-information-disclosure/SKILL.md` | `attack-information-disclosure` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-k8s/SKILL.md` | `k8s-assessment` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-laravel/SKILL.md` | `attack-laravel` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-ldap/SKILL.md` | `attack-ldap` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-lfi/SKILL.md` | `attack-lfi` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-llm-ai/SKILL.md` | `attack-llm-ai` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-mass-assignment/SKILL.md` | `attack-mass-assignment` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-mcp-security/SKILL.md` | `attack-mcp-security` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-metrics-exposure/SKILL.md` | `attack-metrics-exposure` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-mfa-bypass/SKILL.md` | `attack-mfa-bypass` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-misc/SKILL.md` | `attack-misc` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-nestjs/SKILL.md` | `attack-nestjs` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-nextjs/SKILL.md` | `attack-nextjs` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-nodejs/SKILL.md` | `attack-nodejs` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-nosqli/SKILL.md` | `attack-nosqli` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-ntlm-info/SKILL.md` | `attack-ntlm-info` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-oauth/SKILL.md` | `attack-oauth` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-open-redirect/SKILL.md` | `attack-open-redirect` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-prototype-pollution/SKILL.md` | `attack-prototype-pollution` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-race-condition/SKILL.md` | `attack-race-condition` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-rce/SKILL.md` | `attack-rce` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-saml/SKILL.md` | `attack-saml` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-schema-enumeration/SKILL.md` | `attack-schema-enumeration` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-session/SKILL.md` | `attack-session` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-sharepoint/SKILL.md` | `attack-sharepoint` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-source-leak/SKILL.md` | `attack-source-leak` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-springboot/SKILL.md` | `attack-springboot` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-sqli/SKILL.md` | `attack-sqli` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-ssrf/SKILL.md` | `attack-ssrf` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-ssti/SKILL.md` | `attack-ssti` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-subdomain/SKILL.md` | `attack-subdomain-takeover` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-supabase/SKILL.md` | `attack-supabase` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-tls-network/SKILL.md` | `attack-tls-network` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-websocket/SKILL.md` | `attack-websocket` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-wordpress/SKILL.md` | `attack-wordpress` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-write-gap/SKILL.md` | `attack-write-gap` | not mapped — review for new skill or merge |
| recon-skills | `redteam/hunt-xss/SKILL.md` | `attack-xss` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/hunt-xxe/SKILL.md` | `attack-xxe` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/llm-prompt-injection/SKILL.md` | `attack-llm-prompt-injection` | not mapped — review for new skill or merge |
| recon-skills | `redteam/m365-entra-attack/SKILL.md` | `attack-m365-entra-attack` | not mapped — review for new skill or merge |
| recon-skills | `redteam/meme-coin-audit/SKILL.md` | `attack-meme-coin-audit` | not mapped — review for new skill or merge |
| recon-skills | `redteam/mid-engagement-ir-detection/SKILL.md` | `attack-mid-engagement-ir-detection` | not mapped — review for new skill or merge |
| recon-skills | `redteam/offensive-osint/SKILL.md` | `attack-offensive-osint` | not mapped — review for new skill or merge |
| recon-skills | `redteam/okta-attack/SKILL.md` | `attack-okta-attack` | not mapped — review for new skill or merge |
| recon-skills | `redteam/ops-proxyns/SKILL.md` | `attack-ops-proxyns` | not mapped — review for new skill or merge |
| recon-skills | `redteam/osint-methodology/SKILL.md` | `attack-osint-methodology` | not mapped — review for new skill or merge |
| recon-skills | `redteam/password-spray-methodology/SKILL.md` | `attack-password-spray-methodology` | not mapped — review for new skill or merge |
| recon-skills | `redteam/recon-sector-expansion/SKILL.md` | `attack-recon-sector-expansion` | not mapped — review for new skill or merge |
| recon-skills | `redteam/recon-sector/SKILL.md` | `attack-recon-sector` | not mapped — review for new skill or merge |
| recon-skills | `redteam/redteam-mindset/SKILL.md` | `attack-redteam-mindset` | not mapped — review for new skill or merge |
| recon-skills | `redteam/redteam-report-template/SKILL.md` | `attack-redteam-report-template` | not mapped — review for new skill or merge |
| recon-skills | `redteam/report-writing/SKILL.md` | `attack-report-writing` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/security-arsenal/SKILL.md` | `attack-security-arsenal` | not mapped — review for new skill or merge |
| recon-skills | `redteam/supply-chain-attack-recon/SKILL.md` | `attack-supply-chain-attack-recon` | not mapped — review for new skill or merge |
| recon-skills | `redteam/triage-validation/SKILL.md` | `attack-triage-validation` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/vmware-vcenter-attack/SKILL.md` | `attack-vmware-vcenter-attack` | not mapped — review for new skill or merge |
| recon-skills | `redteam/web2-recon/SKILL.md` | `attack-web-recon` | candidate exists — semantic merge/review required |
| recon-skills | `redteam/web3-audit/SKILL.md` | `attack-web3-audit` | not mapped — review for new skill or merge |
| recon-skills | `redteam/wordpress-cors-xmlrpc-rce-chain/SKILL.md` | `attack-wordpress-cors-xmlrpc-rce-chain` | not mapped — review for new skill or merge |
| recon-skills | `redteam/wp-plugin-automation/SKILL.md` | `attack-wp-plugin-automation` | not mapped — review for new skill or merge |
| recon-skills | `redteam/wp-plugin-cve-hunt/SKILL.md` | `attack-wp-plugin-cve-hunt` | not mapped — review for new skill or merge |
| recon-skills | `redteam/wstg-web-pentest/SKILL.md` | `attack-wstg-web-pentest` | not mapped — review for new skill or merge |


## Second adapted batch (2026-10-11)

The following additional source areas have CyberStrike-native drafts on this branch. These are adapted playbooks with source attribution, not verbatim mirrors:

| CyberStrike skill | Source area | Review status |
|---|---|---|
| `attack-api-misconfig` | Claude-BugHunter `hunt-api-misconfig` | Draft added; runtime support unverified |
| `attack-ato` | Claude-BugHunter `hunt-ato` | Draft added; runtime support unverified |
| `attack-business-logic` | Claude-BugHunter `hunt-business-logic` | Draft added; runtime support unverified |
| `attack-clickjacking` | Claude-BugHunter `hunt-clickjacking` | Draft added; runtime support unverified |
| `attack-grpc` | Claude-BugHunter gRPC testing | Draft added; runtime support unverified |
| `attack-cloud-iam` | Claude-BugHunter `cloud-iam-deep` | Draft added; runtime support unverified |
| `attack-deserialization` | Claude-BugHunter `hunt-deserialization` | Draft added; runtime support unverified |
| `attack-api-noauth` | recon-skills API no-auth assessment area | Draft added; runtime support unverified |
| `attack-wordpress` | Claude-BugHunter WordPress assessment | Draft added; runtime support unverified |
| `attack-apk-redteam-pipeline` | Claude-BugHunter Android APK pipeline | Draft added; runtime support unverified |
| `attack-bugcrowd-reporting` | Claude-BugHunter Bugcrowd reporting | Draft added; runtime support unverified |
| `attack-cicd-security` | Claude-BugHunter CI/CD security | Draft added; runtime support unverified |

These rows describe work added in the feature branch. They are not claims that the matching upstream skill has been fully reconciled or that every procedure has been independently validated.


## Third adapted batch (2026-10-11)

| CyberStrike skill | Source area | Review status |
|---|---|---|
| `attack-captcha-bypass` | Claude-BugHunter `hunt-captcha-bypass` | Draft added; runtime support unverified |
| `attack-cloud-misconfig` | Claude-BugHunter `hunt-cloud-misconfig` | Draft added; runtime support unverified |
| `attack-mcp-security` | recon-skills `redteam/hunt-mcp-security` | Draft added; runtime support unverified |
| `attack-llm-security` | Claude-BugHunter `hunt-llm-ai`; recon-skills `redteam/llm-prompt-injection` | Draft added; runtime support unverified |
| `attack-email-security` | recon-skills `recon/email-security` | Draft added; runtime support unverified |
| `attack-401-403-bypass` | recon-skills `recon/401-403-bypass` | Draft added; runtime support unverified |
| `attack-source-leak` | Claude-BugHunter `hunt-source-leak`; recon-skills `recon/source-leak-hunt` | Draft added; runtime support unverified |
| `attack-firebase-supabase` | recon-skills Firebase/Supabase assessment | Draft added; runtime support unverified |
| `attack-supply-chain-recon` | Claude-BugHunter and recon-skills supply-chain reconnaissance | Draft added; runtime support unverified |


## Fourth adapted batch (2026-10-11)

| CyberStrike skill | Source area | Review status |
|---|---|---|
| `attack-ldap` | Claude-BugHunter LDAP assessment | Draft added; runtime support unverified |
| `attack-k8s` | Claude-BugHunter and recon-skills Kubernetes assessment | Draft added; runtime support unverified |
| `attack-vcenter` | Claude-BugHunter and recon-skills vCenter assessment | Draft added; runtime support unverified |
| `attack-m365-entra` | Claude-BugHunter M365/Entra assessment | Draft added; runtime support unverified |
| `attack-okta` | Claude-BugHunter Okta assessment | Draft added; runtime support unverified |
| `attack-brute-force` | Claude-BugHunter brute-force controls | Draft added; runtime support unverified |
| `attack-ntlm` | Claude-BugHunter NTLM information/exposure | Draft added; runtime support unverified |
| `attack-lfi` | Claude-BugHunter local file inclusion | Draft added; runtime support unverified |
| `attack-nosqli` | Claude-BugHunter NoSQL injection | Draft added; runtime support unverified |
| `attack-session-management` | Claude-BugHunter session assessment | Draft added; runtime support unverified |
