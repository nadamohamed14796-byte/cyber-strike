# Wordlist Sources

This file is the canonical source registry for externally maintained wordlists and payload collections used by CyberStrike. Keep source URLs here rather than duplicating repository links across skills.

| Source | Intended category | Repository |
|---|---|---|
| WordList | General-purpose wordlists | https://github.com/orwagodfather/WordList |
| My-WordLISTs | Personal/custom wordlists | https://github.com/orwagodfather/My-WordLISTs |
| XSS-Payloads | XSS test payloads | https://github.com/orwagodfather/XSS-Payloads |
| SQL-Wordlist | SQL-related wordlists and test strings | https://github.com/orwagodfather/SQL-Wordlist |

## Usage notes

- Treat these repositories as **source references**; this registry does not imply their contents have been downloaded, vendored, or verified.
- Before importing files, inspect each repository's directory structure and license, select the relevant files, and record the upstream revision and SHA-256 checksums.
- Deduplicate imported entries while preserving source attribution; do not silently overwrite existing wordlists.
- Select a list for the specific task (for example, content discovery versus XSS or SQL injection testing) rather than combining every list into one large payload file.
- Use payloads only against assets where testing is authorized, and follow the target's rate limits and program rules.
