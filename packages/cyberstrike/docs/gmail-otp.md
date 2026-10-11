# Gmail OTP integration

CyberStrike can read a recent verification email using Google's OAuth API. It does **not** sign in to Gmail using a Google password, and it never needs the Gmail URL, email password, or a browser cookie saved in the repository.

## Required OAuth configuration

Configure these variables in the environment of the CyberStrike process (do not put values in source files, committed .env files, prompts, logs, or target notes):

- `CYBERSTRIKE_GMAIL_OAUTH_CLIENT_ID`
- `CYBERSTRIKE_GMAIL_OAUTH_CLIENT_SECRET`
- `CYBERSTRIKE_GMAIL_OAUTH_REFRESH_TOKEN`

The refresh token must be issued for `https://www.googleapis.com/auth/gmail.readonly`. Use a Google Cloud OAuth client you control, enable the Gmail API, complete Google's consent flow, and store the refresh token in your local secret manager or private process environment. Do not paste OAuth secrets into ChatGPT.

## Tool use

Call `auth_manager` with `action: "gmail_otp"`, the website's `site_url`, and optionally `after` (Unix timestamp in milliseconds) to limit results to messages received after the login attempt began. The tool requests permission before reading mail.

For safety, the current implementation only considers recent verification messages sent from the website's exact hostname or a subdomain. It intentionally ignores third-party mail providers, because broad inbox scanning could disclose unrelated messages. If a site sends codes from a third-party domain, add a reviewed per-site sender allowlist before supporting it; do not weaken this check globally.

## Current limitations

- This module reads codes; it does not yet automate filling a login or registration form in the hackbrowser worker.
- Google consent, account recovery, CAPTCHA, passkeys, and unsupported MFA require a human.
- OTP extraction is heuristic. The agent must verify that the message and requested login flow correspond to the same site and session before using the code.
- The refresh token is a sensitive secret. Keep it outside Git and rotate/revoke it in Google Account security settings if exposed.