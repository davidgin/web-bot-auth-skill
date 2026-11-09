# Security policy

This project is security-relevant code: a bug in the verifier can let forged or replayed requests through.

**Please do not open a public issue for vulnerabilities.** Report them privately through GitHub's "Report a vulnerability" button on the Security tab of this repository. Include a minimal request (headers, body, URL, time) that reproduces the problem and the outcome you expected.

In scope: anything that makes `Verifier.verify` return `verified` or `signed_untrusted` for a request it should reject; replay bypasses; SSRF or resource exhaustion through key directory handling; crashes on malformed input. Weaknesses in the Web Bot Auth draft itself should go to the IETF web-bot-auth working group as well.
