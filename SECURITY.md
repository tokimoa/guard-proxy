# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Guard Proxy, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **takuya.omi@tokimoa.jp**

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

The following are in scope for security reports:

- Bypass of scanning/blocking logic (malicious package not detected)
- Proxy vulnerabilities that could be exploited by a malicious registry response
- Information disclosure (credentials, API keys leaked in logs or responses)
- Denial of service against the proxy itself

The following are out of scope:

- Detection gaps for novel/unknown attack techniques (these are feature requests, not vulnerabilities)
- Issues in upstream dependencies (report these to the respective projects)
- Issues requiring physical access to the machine running Guard Proxy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:

1. Release a patched version
2. Publish a GitHub Security Advisory
3. Credit the reporter (unless they prefer anonymity)
