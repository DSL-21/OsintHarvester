# Security Audit and Hardening Notes

## Scope

This is a targeted source and configuration review of the Android app, its URL handling, network client, extraction pipeline, dependencies, manifest, and repository automation. It is not an independent penetration test, formal certification, or physical-device assessment.

## Issues identified in the original implementation

- User-entered URLs were accepted with weak scheme checks.
- The OkHttp client used default redirect behavior and had no explicit request timeouts.
- Responses were read fully into memory without a maximum byte count.
- DNS results were not checked against private and special-use address ranges.
- Deep crawling could follow links without a strict origin comparison that normalized the target URL safely.
- Some response bodies were not reliably closed.
- HTTP response headers could expose session cookies.
- The API-key detector printed matching values in full.
- The directory checker attempted sensitive paths such as `.env`, `.git`, backup, configuration, and administrative locations.
- Scan jobs were not lifecycle-scoped and there was no cancellation control.
- Android cloud/device backup was enabled.
- Unit tests were only the template arithmetic test; the project had no CI workflow or security guidance.
- Development IDE/cache artifacts were tracked in Git.

## Hardening implemented for 1.1.0

- Restrict target URLs to HTTPS on port 443 and reject embedded credentials and local hostnames.
- Add a DNS implementation that resolves once, validates every returned IP, and passes the checked addresses to OkHttp. Private, loopback, link-local, carrier-grade NAT, multicast, documentation, and reserved ranges are rejected.
- Disable redirects and automatic connection retries; disable system proxies so they cannot bypass the validated DNS resolver.
- Apply explicit connect, read, write, and total call timeouts.
- Bound HTML, API, and robots.txt response sizes; close response resources with structured cleanup.
- Keep crawl links on the exact same origin and enforce page, depth, and per-page link limits.
- Strip target query strings and fragments before crawl storage and external lookups. The Wayback lookup uses only the site origin.
- Redact cookie and authentication headers, strip query/fragment components from social and archive URLs, and mask common secret-like values plus recognizable API-key formats in rendered output.
- Limit the total number and length of visible results.
- Replace sensitive path probing with HEAD requests to a fixed list of public metadata resources, splitting the lists to avoid duplicate requests.
- Use a lifecycle-scoped coroutine job and add a user-visible cancel control.
- Disable Android backup and cleartext traffic.
- Add unit tests for URL validation, IP range checks, and sensitive URL component removal.
- Update OkHttp, jsoup, and Gson; add pinned GitHub Actions CI and Dependabot configuration.
- Remove IDE/cache output from the tracked tree and ignore future generated artifacts.

## Core and intelligence improvements for 1.2.0

- Run independent collection modules concurrently with a fixed maximum of four module jobs.
- Track every active OkHttp call in a thread-safe in-memory set so cancellation stops all concurrent requests.
- Validate direct IPv4 and IPv6 target literals before connecting; IP literals cannot bypass DNS-based address checks.
- Expand DNS collection through the Google Public DNS JSON-over-HTTPS API for A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and DMARC TXT records.
- Resolve authoritative RDAP services from the IANA domain bootstrap registry and accept only HTTPS default-port endpoints.
- Parse DNS and RDAP responses with bounded payload sizes.
- Keep the design stateless: no database, persistent cache, automatic scan history, or background service was added.

## English UI update for 1.2.1

- Move visible Android labels and controls into the default English string resources.
- Translate scan progress, cancellation, errors, and all result headings/messages to English.
- Keep the application English-only; no locale-specific strings or runtime translation dependency is added.
- No scan, network, storage, or security behavior is changed by this language-only update.

## Remaining limitations

- Some OSINT providers are external services. Optional lookups disclose the selected domain or public IP to the provider shown in the README, including Google Public DNS, IANA bootstrap data, and the selected RDAP registry.
- The API-key detector uses a small set of patterns and can produce false positives or miss secret formats; masking reduces accidental exposure but is not a complete secret-scanning engine.
- Public IP range checks are conservative and may reject special-use or unusual addresses that are technically reachable.
- Some sites reject HEAD requests or rate-limit automated clients, so certificate and metadata checks may report unavailable even when a browser can load the resource.
- No physical-device/OEM matrix, manual network interception test, or independent penetration test has been performed yet.

## Verification status

The CI workflow is intended to run Android lint, JVM unit tests, and debug/release assembly. Results must be reviewed on the commit/PR before treating the build as verified. A green CI run does not prove the absence of vulnerabilities.
