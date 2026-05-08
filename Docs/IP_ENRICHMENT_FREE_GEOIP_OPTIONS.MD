# IP Enrichment Free GeoIP Options

Audit date: 2026-04-12

## Current state

DomainDetective already has a first-class IP enrichment check. `IpEnrichmentAnalysis` discovers apex, MX, NS, and caller-provided IPs, then adds PTR, RDAP network data, ASN hints, CIDR, country, and region where available.

The existing offline GeoIP implementation is intentionally tiny. `GeoIpAnalysis` loads an embedded `Data/geoip.csv` resource, but that CSV currently contains only three point IP entries:

- `1.1.1.1` -> AU / Queensland
- `8.8.8.8` -> US / California
- `9.9.9.9` -> US / New Jersey

That makes the current GeoIP path useful for plumbing and tests, not for broad production enrichment.

Other free or mostly free enrichment already exists:

- IP RDAP lookups via `RdapClient`, currently defaulting to `https://rdap.org`.
- RIPEstat `prefix-overview` lookups in several analyses for BGP/ASN-style context.
- Web static scan host enrichment that does DNS, RDAP, CIDR, country, ASN, AS name, and simple edge provider inference.
- DMARC aggregate enrichment that uses the same tiny GeoIP database for country and RIPEstat for ASN.

## Free provider landscape

| Option | Free data/API shape | Fit for DomainDetective | Caveats |
| --- | --- | --- | --- |
| IPinfo Lite | Free API and database for country-level geolocation and ASN data. CSV, MMDB, JSON, and Parquet database downloads are advertised. | Strong candidate for default opt-in free enrichment because it directly maps to DD's country and ASN fields. | Requires attribution under CC BY-SA 4.0. Account/token is required for API use. City-level details require paid products. |
| DB-IP Lite | Free IP to City Lite and IP to ASN Lite databases. CSV and MMDB formats. Updated monthly. | Good offline database option if attribution is acceptable and package size is handled outside the NuGet library. | Requires attribution. Lite data has reduced coverage and accuracy. City Lite is large; ASN Lite is smaller. |
| MaxMind GeoLite | Free downloadable databases and web services with Country, City, and ASN data. CSV and MMDB formats. | Technically mature option, especially with MMDB readers. | Requires account/license key, attribution, and update compliance. The EULA requires old databases to be deleted within 30 days of a new release. Web service is limited, and free City is not recommended for commercial use cases. |
| IP2Location LITE | Free personal/commercial use with attribution. IP2Location LITE and ASN LITE are available after signup. | Usable offline option, especially if DD wants country/region/city and separate ASN data. | Attribution required. Signup required. LITE precision and field coverage are limited compared with commercial editions. |
| ip-api.com free JSON endpoint | No API key. Returns geo, ASN, ISP/org, reverse, hosting/proxy/mobile hints. | Useful for ad-hoc manual checks, but not a good default library integration. | Free endpoint is HTTP only, 45 requests/minute per source IP, and disallows commercial use. |
| RIPEstat prefix-overview | Public API already used in DD. No request count limit, but limits concurrent requests per source IP and asks regular users to identify with `sourceapp`. | Good to keep for BGP/routing ASN context, not a full GeoIP replacement. | Not a complete GeoIP provider; use sourceapp and centralize throttling/cache behavior. |

## Recommended direction

1. Keep the current `IpEnrichmentAnalysis` as the orchestration point.
2. Introduce a small provider abstraction, for example `IIpEnrichmentProvider` or narrower `IGeoIpLookupProvider` and `IAsnLookupProvider`.
3. Make the built-in `GeoIpAnalysis` range-aware instead of exact-IP-only. Today it stores `Dictionary<string, GeoLocationInfo>`, so it cannot load normal GeoIP databases that publish IP ranges.
4. Do not embed a full free GeoIP database in the NuGet package by default. The DBs are too large and have attribution/update obligations. Prefer:
   - a documented external database path,
   - a local cache directory,
   - a refresh command or helper,
   - and a tiny embedded sample only for tests.
5. Add one free offline provider first:
   - Best practical default: IPinfo Lite if attribution and CC BY-SA are acceptable.
   - Best simple MMDB/CSV fallback: DB-IP Lite if monthly updates and attribution are acceptable.
6. Add optional online lookups second, behind explicit settings:
   - IPinfo Lite API for country/ASN where a token is supplied.
   - MaxMind GeoLite web service only when a license key is supplied.
   - Avoid `ip-api.com` as an automated default because the free endpoint is HTTP-only and non-commercial.
7. Centralize ASN/BGP lookups. RIPEstat `prefix-overview` calls currently appear in multiple analyses, so a shared service with caching, sourceapp, concurrency caps, and retry handling would improve quality without changing providers.
8. Surface provenance in report rows. Add a `Source` or `Provider` field so users can tell whether country/ASN came from RDAP, offline GeoIP, IPinfo, DB-IP, MaxMind, or RIPEstat.
9. Add TTL-based caching for all network enrichments keyed by IP and provider. This matters for typosquatting scans and web static scans where repeated domains can reuse the same infrastructure.
10. Keep free data licensing visible:
    - Add attribution hooks in HTML/Markdown/Office reports.
    - Record database version/release date in analysis metadata.
    - Document update expectations per provider.

## GitHub-hosted database strategy

Technically, DomainDetective can download free GeoIP/ASN databases, store an approved snapshot on GitHub, and use it on demand. The safer approach is to treat the database as an optional runtime asset, not as source code.

Recommended shape:

1. Keep only metadata and downloader code in the main repository:
   - provider,
   - release date,
   - source URL,
   - license URL,
   - attribution text,
   - SHA256 checksum,
   - expected compressed/uncompressed size.
2. Publish approved database snapshots as GitHub Release assets or in a separate data repository. Avoid committing large CSV/MMDB files into the main git history.
3. Add a `dd geoip update` style command or helper that:
   - checks the metadata file,
   - downloads the selected provider snapshot,
   - verifies the SHA256 checksum,
   - stores it in a local cache directory,
   - records provider/version metadata for reports.
4. Use the cached database only when the user enables the provider or when the file is already present. Keep the embedded `Data/geoip.csv` as a tiny test/sample fallback.
5. Add provider attribution to reports whenever a hosted database contributes a field.

Provider suitability for GitHub storage:

| Provider | Store snapshot on public GitHub? | Notes |
| --- | --- | --- |
| DB-IP Lite | Best candidate, subject to attribution. | DB-IP Lite is licensed under CC BY 4.0 and the download pages explicitly require attribution. Its ASN MMDB is small enough for GitHub release assets; City CSV is larger and should not be committed to normal git. |
| IPinfo Lite | Likely possible if attribution and CC BY-SA 4.0 obligations are acceptable. | The Lite product is free, supports API/database downloads, and permits commercial/non-commercial use with attribution, but ShareAlike may affect downstream packaging choices. |
| MaxMind GeoLite | Do not store in public GitHub by default. | Requires account/license key, attribution, update compliance, and timely deletion of stale data after new releases. Prefer a user-side downloader that uses the user's MaxMind key. |
| IP2Location LITE | Avoid public redistribution unless licensing is reviewed for the intended use. | IP2Location's licensing page points commercial/external redistribution at a Redistribution License, so a public snapshot repository is risky without explicit confirmation. |
| ip-api.com | Not applicable. | It is a hosted API, not a downloadable database, and the free endpoint is not a good automated default. |

GitHub storage notes:

- Normal repository files over 100 MiB are blocked by GitHub.
- GitHub warns on files over 50 MiB, and recommends keeping repositories small.
- GitHub Releases are better for distributing large binary assets than normal git history. Each release asset must be under 2 GiB, with up to 1000 assets per release.
- Git LFS is technically possible, but it adds quota/bandwidth behavior that can surprise users and CI. Releases or an external object store are a better fit for monthly/daily database snapshots.

## Small implementation plan

1. Add model fields:
   - `IpEnrichmentRow.Provider`
   - `IpEnrichmentRow.CountrySource`
   - `IpEnrichmentRow.AsnSource`
   - optional database/version metadata on `IpEnrichmentAnalysis`
2. Replace exact-IP GeoIP lookup with a range lookup interface:
   - Parse IPv4 and IPv6 ranges from CSV.
   - Store sorted ranges per address family.
   - Binary search by numeric IP value.
3. Add `Data/geoip.sample.csv` or keep the current embedded CSV as sample data only.
4. Add a user-configurable external database path, likely on `IpEnrichmentAnalysis` and `DomainHealthCheck` settings.
5. Add an optional IPinfo Lite API provider with:
   - token from parameter or environment variable,
   - per-IP cache,
   - cancellation support,
   - response model for `asn`, `as_name`, `as_domain`, `country_code`, `country`, `continent`.
6. Add docs and tests for:
   - exact lookup fallback,
   - range lookup for IPv4 and IPv6,
   - provider precedence: offline GeoIP, RDAP fallback, online provider if configured,
   - attribution metadata in converted report views.

## Sources checked

- MaxMind GeoLite developer docs: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/
- MaxMind GeoLite EULA: https://www.maxmind.com/en/geolite2/eula
- DB-IP IP to City Lite: https://db-ip.com/db/download/ip-to-city-lite
- DB-IP IP to ASN Lite: https://db-ip.com/db/download/ip-to-asn-lite
- IPinfo Lite: https://ipinfo.io/lite
- IPinfo developer docs: https://ipinfo.io/developers
- IP2Location LITE database page: https://lite.ip2location.com/database/db3-ip-country-region-city
- IP2Location official LITE database overview: https://www.ip2location.com/database/lite
- ip-api JSON docs: https://ip-api.com/docs/api:json
- RIPEstat Data API docs: https://stat.ripe.net/docs/data-api/ripestat-data-api
