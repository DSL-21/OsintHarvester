# Security Policy

## Intended use

OSINT Harvester is intended for passive collection of information that is already publicly available on websites and domain infrastructure.

Use it only against systems you own or for which you have explicit authorization. Follow the target's terms, applicable law, and reasonable request-rate expectations.

The app intentionally rejects:
- HTTP and non-standard ports
- Localhost, private, link-local, and other non-public IP address ranges
- Redirects to other URLs
- Cross-origin crawl links
- Sensitive path guessing such as `.env`, `.git`, backup, configuration, and administrative directories

Do not use the app to bypass authentication, enumerate private data, brute-force credentials, exploit vulnerabilities, or disrupt services.

## Reporting a vulnerability

Please report security issues privately through GitHub's security advisory feature:

https://github.com/DSL-21/OsintHarvester/security/advisories/new

Include the affected version, Android version, reproduction steps, impact, and any relevant logs. Do not include real credentials, access tokens, or other personal data in a report.

Please allow reasonable time for triage and a fix before public disclosure.
