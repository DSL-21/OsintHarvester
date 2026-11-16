# OSINT Harvester

A native Android application for collecting publicly available website and domain intelligence.

OSINT Harvester is designed for **authorized, read-only reconnaissance** of public web properties. It collects visible metadata and public DNS / certificate / archive information; it is not a vulnerability exploitation or credential-testing tool.

## Features

- Extract publicly visible email addresses and phone numbers from HTML pages
- Discover linked social profiles using parsed URL hostnames
- Inspect HTML metadata, comments, response headers, and common technology indicators
- Detect likely API-key patterns while masking matching values in the UI
- Crawl same-origin HTTPS pages with configurable depth
- Query public certificate transparency data through crt.sh
- Look up DNS addresses, TLS certificate details, WHOIS / reverse-IP information, and Wayback availability
- Read public `robots.txt`, sitemap, security.txt, favicon, humans.txt, and manifest metadata

## Safety restrictions

- Only HTTPS targets on the default port 443 are accepted.
- DNS resolution rejects loopback, private, link-local, carrier-grade NAT, multicast, documentation, and reserved address ranges.
- The HTTP client connects using the validated DNS answers, does not use a system proxy, and has redirects and connection retries disabled.
- Deep crawling stays on the exact same HTTPS origin (scheme, hostname, and port).
- Network timeouts and response-size limits are enforced.
- A crawl is limited to 20 pages, 10 links per page, and a maximum depth of 5.
- Public metadata checks use a short, fixed list of standard resources. The app does not probe `.env`, `.git`, administrative panels, backup folders, or configuration paths.
- Cookie and authentication response headers are redacted. Likely API keys and common secret assignments are masked before display.
- Scan results are held in the activity UI and are not written to a database or exported by this version. Android backup is disabled.

These controls reduce risk but are not a guarantee of security. Only scan systems you own or have explicit permission to assess. Do not submit credentials, session tokens, or sensitive query parameters as target URLs.

## Third-party services

Optional lookups send the queried domain or IP to the selected public service:

| Feature | Provider | Data sent |
| --- | --- | --- |
| Subdomain / certificate transparency | crt.sh | Domain name |
| WHOIS and reverse-IP | HackerTarget API | Domain name or public IP address |
| Archived page availability | Internet Archive / Wayback Machine | Website origin (scheme and host) |

These services have their own logging and privacy policies. Leave the corresponding option unchecked when you do not want to query that provider.

## Build

Requirements:
- Android Studio with Android SDK 36
- JDK 17 for Gradle / Android Gradle Plugin
- Gradle wrapper included in this repository

Build and test:

```bash
bash ./gradlew lintDebug testDebugUnitTest assembleDebug
```

On Windows:

```powershell
.\gradlew.bat lintDebug testDebugUnitTest assembleDebug
```

The Android CI workflow runs lint, JVM unit tests, and both debug and release APK assembly for pushes and pull requests.

## Project security

See [SECURITY.md](SECURITY.md) for responsible-use and vulnerability-reporting guidance, and [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) for the hardening review.
