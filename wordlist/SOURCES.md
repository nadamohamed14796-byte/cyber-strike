# Wordlist Sources

This file is the canonical source registry for externally maintained wordlists and payload collections used by CyberStrike. Keep source URLs here rather than duplicating repository links across skills.

## Bug bounty and general-purpose collections

| Source | Intended category | Repository |
|---|---|---|
| SecLists | General security testing lists: discovery, fuzzing, credentials, and more | https://github.com/danielmiessler/SecLists |
| Assetnote Wordlists | Frequently updated, technology-focused discovery lists | https://wordlists.assetnote.io/ |
| awesome-wordlists | Curated index of wordlists for bruteforcing and fuzzing | https://github.com/gmelodie/awesome-wordlists |
| OneListForAll | Web content discovery and fuzzing | https://github.com/six2dez/OneListForAll |
| fuzz4bounty | Bug bounty wordlists | https://github.com/0xPugal/fuzz4bounty |
| Bug-Bounty-Wordlists | Bug bounty testing collections | https://github.com/Karanxa/Bug-Bounty-Wordlists |
| Wordlists (kkrypt0nn) | General-purpose wordlist collection | https://github.com/kkrypt0nn/wordlists |
| Wordlists (pkgforge-security) | Curated and automated bug bounty wordlists | https://github.com/pkgforge-security/Wordlists |
| Wordlist-Hub | Bug bounty wordlists | https://github.com/bhavesh-pardhi/Wordlist-Hub |
| WordList (orwagodfather) | General-purpose wordlists | https://github.com/orwagodfather/WordList |
| My-WordLISTs | Personal/custom wordlists | https://github.com/orwagodfather/My-WordLISTs |

## Focused discovery lists

| Source | Intended category | Repository |
|---|---|---|
| leaky-paths | Sensitive paths and commonly exposed API/DevOps endpoints | https://github.com/ayoubfathi/leaky-paths |
| bruteforce-lists | Targeted path and content discovery lists | https://github.com/random-robbie/bruteforce-lists |
| n0kovo_subdomains | Subdomain enumeration | https://github.com/n0kovo/n0kovo_subdomains |
| UltimateCMSWordlists | CMS-specific discovery | https://github.com/JavierOlmedo/UltimateCMSWordlists |
| subdirectories-discover | Directory and file discovery | https://github.com/aels/subdirectories-discover |

## Payload collections

| Source | Intended category | Repository |
|---|---|---|
| XSS-Payloads | XSS testing payloads | https://github.com/orwagodfather/XSS-Payloads |
| SQL-Wordlist | SQL-related wordlists and test strings | https://github.com/orwagodfather/SQL-Wordlist |

## Usage notes

- Treat these repositories as **source references**; this registry does not imply their contents have been downloaded, vendored, or verified.
- Before importing files, inspect each repository's directory structure and license, select the relevant files, and record the upstream revision and SHA-256 checksums.
- Deduplicate imported entries while preserving source attribution; do not silently overwrite existing wordlists.
- Select a list for the specific task rather than combining every list into one large payload file.
- Use wordlists and payloads only against assets where testing is authorized, and follow target rate limits and program rules.
