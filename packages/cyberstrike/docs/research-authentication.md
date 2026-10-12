# Research source authentication

CyberStrike Research first tries to read reports without authentication. It persists discovered URLs and learning progress in SQLite, so rerunning `research sync` skips reports already in the durable queue or external knowledge store and resumes work that is still queued. A report that is learned or rejected is not fetched again automatically.

## When a source requires login

If a report or index page requires a session, CyberStrike records a `blocked_auth` state instead of repeatedly fetching a login page. Public pages continue to be collected. After a valid source session is configured, `research sync` and `research learn` can automatically retry blocked report URLs for that source, subject to the retry cooldown.

Credentials are read only from the process environment and are not stored in the queue or research knowledge. Never paste session cookies or tokens into committed files, command-line arguments, bug reports, or chat. Do not bypass MFA, CAPTCHA, paywalls, or access restrictions. Automatic account registration is intentionally not attempted: it can require a real email address, verification codes, acceptance of site terms, and account-owner consent.

## Configure an existing authorized session

1. Open the source website and sign in to an account you are authorized to use.
2. Copy the session cookie header or the site's documented bearer/API authorization value from your browser's developer tools. Use only the minimum credentials needed for reading the report.
3. In the same terminal where CyberStrike will run, set the source-specific environment variable. The source ID is uppercased and non-alphanumeric characters become underscores. For example, for `portswigger`:

```bash
read -rsp "PortSwigger Cookie header: " CYBERSTRIKE_RESEARCH_COOKIE_PORTSWIGGER
printf '\n'
export CYBERSTRIKE_RESEARCH_COOKIE_PORTSWIGGER
cyberstrike research sync portswigger
```

For an API bearer token, use `CYBERSTRIKE_RESEARCH_AUTHORIZATION_PORTSWIGGER` instead. For HackerOne Hacktivity, use the suffix `HACKERONE_HACKTIVITY`. Check `cyberstrike research sources` to see the exact variable names for every configured source; it reports only whether a session is configured and never prints the secret value.

To remove a session from the current shell, run `unset CYBERSTRIKE_RESEARCH_COOKIE_PORTSWIGGER CYBERSTRIKE_RESEARCH_AUTHORIZATION_PORTSWIGGER`.

## Retry behavior

- `cyberstrike research sync [source]`: discovers new reports, skips known report URLs, learns queued reports, and resumes eligible auth-blocked work if a source session is configured.
- `cyberstrike research learn --source [source]`: processes only the selected source's durable queue.
- `cyberstrike research retry-auth --source [source]`: explicitly requeues blocked work after credentials are changed. It bypasses the automatic cooldown, so use it only after updating or renewing the session.
- `cyberstrike research queue-stats [source]`: shows counts, including `blocked_auth`.

An expired cookie or insufficient permission will block the report again. CyberStrike does not claim a report was read or learned unless the content passed its ingestion checks.
