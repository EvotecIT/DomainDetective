# HTTP Posture (Web / Headers)

## What this check does

The HTTP posture check performs an HTTPS request to a host and captures:

- Reachability, status code, response time
- Redirect chain (effective URL)
- HTTP protocol version hints (HTTP/2, HTTP/3 when available)
- Modern security header posture (presence + basic value validation)
- HSTS parsing (max-age, includeSubDomains, preload token; preload eligibility)
- Optional body scan for mixed content and insecure `<form action="http://...">` on HTTPS pages
- Evidence buckets:
  - security headers (present + missing)
  - information disclosure headers (best-effort)
  - caching headers (best-effort)
  - deprecated headers (present + missing)

## Primary implementation

- `DomainDetective.HttpAnalysis`
- `DomainDetective.HttpRequestOptions` (request customization)

### Request customization knobs

`HttpRequestOptions` supports:

- Method (`HEAD`/`GET`/`POST`/…)
- Custom request headers
- Cookie header
- Proxy URL
- Optional TLS certificate validation disable (unsafe; off by default)

## Library usage (C#)

```csharp
var hc = new DomainHealthCheck();
await hc.VerifyWebsiteHttps("example.com");

// Customized request options
var opts = new HttpRequestOptions
{
    Method = HttpRequestMethod.Head,
    ProxyUrl = "http://127.0.0.1:8080"
};
opts.Headers["User-Agent"] = "DomainDetective";

await hc.VerifyWebsiteHttps("example.com", opts, captureBody: false);
```

## Output surfaces

- View: `DomainDetective.Views.HttpInfo` (includes `.Raw` for deep data)
- HTML report: “HTTP” section (summary + findings + evidence tables)
- Word report: “HTTP” section (summary + evidence tables + findings)
- Excel report (net8.0): “HTTP” block (summary + tables)

## Dashboards

Dashboard profiles provide a compact, multi-domain view intended for quick review:

- HTML: `HtmlProfile.Dashboard`
- Excel: `ExcelProfile.Dashboard`

These dashboards include Discovery/Inventory overview tiles plus HTTP/IP posture rollups.

