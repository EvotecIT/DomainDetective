# Sitemap Analysis

The sitemap check validates XML sitemap discovery, sitemap protocol shape, and the URLs listed inside `urlset` documents. It is intended to catch crawlability problems that are easy to miss in a browser, including malformed XML, duplicate `loc` entries, redirects, redirect loops, 4xx/5xx responses, `noindex` signals, and canonical mismatches.

## Coverage

| Area | Checks |
| --- | --- |
| Discovery | `robots.txt` `Sitemap:` directives, conventional `/sitemap.xml`, sitemap indexes, nested sitemap documents |
| XML shape | well-formed XML, expected sitemap namespace, `urlset` vs `sitemapindex`, missing or invalid `loc` |
| Entry metadata | invalid `lastmod`, invalid `changefreq`, invalid `priority`, duplicate `loc` values |
| URL probes | redirect chains, redirect loops, HTTP 4xx/5xx, failed fetches |
| Indexing signals | `X-Robots-Tag` and HTML meta robots `noindex` |
| Canonical signals | HTML `rel=canonical` mismatches against the final URL |

## PowerShell

```powershell
Test-DDSitemap -Subject evotec.pl
Test-DDSitemap -Subject https://example.org/sitemap.xml -MaxUrlProbes 1000
Test-DDSitemap -Subject example.org -NoUrlProbe
```

Useful tuning options:

| Parameter | Purpose |
| --- | --- |
| `-MaxSitemapDocuments` | Caps sitemap documents fetched, including sitemap index children. |
| `-MaxEntries` | Caps parsed `urlset` entries. |
| `-MaxUrlProbes` | Caps live URL probes. Use `0` or `-NoUrlProbe` for XML-only checks. |
| `-MaxRedirects` | Redirect hop limit before reporting a loop. |
| `-NoCanonicalCheck` | Skips HTML `noindex` and canonical inspection. |
| `-NoHttpFallback` | Disables HTTP fallback when HTTPS discovery fails. |

## CLI and Reports

`HealthCheckType.SITEMAP` is available through the shared health-check pipeline and report composition. HTML and Markdown composition include:

- Summary counts for documents, URLs, probes, duplicates, redirects, redirect loops, HTTP errors, `noindex`, and canonical mismatches.
- Sitemap document evidence.
- A retained problem URL table.
- Structured findings, positives, and references.

## Notes

The analysis is intentionally bounded by default. Large sites should raise `MaxEntries` and `MaxUrlProbes` deliberately, especially when probing URL reachability, because every probed sitemap URL results in an HTTP request.
