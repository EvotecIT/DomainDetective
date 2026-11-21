# Domain risk profile

The risk profile answers two questions about a domain: how risky does it look, and how sure is that. It combines evidence DomainDetective already collects into a risk score (0–100) with a separate confidence value (0–1). It sits next to the assessment score rather than replacing it: the assessment grades configuration, the profile looks at registration, reputation, CT, DNS and network evidence.

**Missing evidence lowers confidence, never the score.** A feed that wasn't queried, or an RDAP lookup that timed out, adds no points. It lowers confidence and shows up as a gap with the action that would close it. With low confidence, a score of 0 reads "No risk signals found in the evidence collected", never "safe".

## Where it comes from

`DomainRiskProfileBuilder` reads a `DomainHealthCheck` once any of THREATINTEL, RDAP, WHOIS, CTTIMELINE or IPENRICHMENT ran. `DomainRiskProfileEvaluator` turns the evidence into the profile, and it can also be called directly with your own `DomainRiskEvidence`.

| Area | Evidence | Scored signals | Shown, not scored |
| --- | --- | --- | --- |
| Reputation | Threat feeds (per feed: listed, clean, not queried, failed), domain and host DNSBL | First feed listing +40 (holds the level at High), more feeds +10, a VirusTotal flag +10 (any one engine, so it never decides the level), domain blocklist +20, listed hosts +5 each (max 15) | Feeds answered, lookalikes rated High or Critical |
| Registration | RDAP, then WHOIS: created, expires, status, registrar | Under 30 days +20, under 90 days +12, under a year +5, hold +20, expired +15, over three years −5 | Registrar, privacy service |
| Certificates | CT timeline from DDCT, crt.sh or Cert Spotter | First certificate under 30 days ago +8 (crt.sh full history only), issuance burst +5 | First seen, issuers, certificate count |
| DNS | Inventory, DNSSEC, NS, FCrDNS | DNSSEC bogus +10, mail hosts without FCrDNS +3, DNSSEC secure −3 | DNS and mail provider |
| Network | IP enrichment with hosting attribution | – | Networks, hosting and CDN, countries |
| Web | Web static scan (counts only when it ran) | – | Technologies |

Per-area caps (60, 30, 20, 15, 10, 15) keep one area from carrying the score. Trust signals can lower the total by at most 20. Levels: Low above 0, Medium from 30, High from 55, Critical from 75.

Confidence is the weighted share of evidence that came back. The weights are Reputation 0.30, Registration 0.20, Certificates 0.15, DNS 0.15 and Network 0.10, plus Web 0.10 when the web scan ran. If the level rests on a single source, confidence is capped at 0.74, and the profile names that source. If the level holds without any one source, confidence gets a 0.10 bonus. Below 0.25 the profile is "Not rated".

Country and WHOIS privacy are never scored. Without GeoIP data, the country is the RDAP registration country, and the profile labels it that way.

## Where it shows

- **HTML assessment:** a "How risky is …?" panel opens each domain's profile. Reports with several domains add a "Risk by domain" panel.
- **Word and PDF:** a risk profile block in each domain chapter, and a "Risk by domain" table in the summary.
- **Excel:** three sheets: Risk profile, Risk signals and Evidence coverage.
- **Markdown:** a risk profile section under each domain, and a "Risk by domain" table.
- **JSON:** `DomainAssessment.RiskProfile`.
- **CLI scan result:** `Risk`, `Network` (addresses, ASNs, hosting), `Certificates` (first seen, issuers) and `Web.Technologies`.

All wording comes from `AssessmentReportWording`.

## Areas and configuration scores

The checks behind the profile (RDAP, WHOIS, DNSBL, threat intel, typosquatting, CT timeline, IP enrichment and neighbours) form their own **Reputation** area. Its row in "Area by area" shows the risk verdict and how much evidence was seen. DANE now sits under Mail.

Domain and area scores count the scored checks whose evidence is complete, and they show the share they rest on ("83% of checks judged"). A check that couldn't be judged is left out of the score and named, instead of hiding the whole score. "Not scored" remains only when nothing in the area could be judged.

Checks that only gather data (inventory, enrichment, discovery and registration lookups) never fail a domain because a lookup failed. That failure counts as missing evidence. What they actually find still counts.

## Hosting and CDN ranges

`IpEnrichmentRow` names the hosting provider of each address from the ranges that AWS, Google Cloud, Cloudflare, Fastly and Akamai publish. The data ships as `Data/hosting_ranges.tsv.gz` (`HostingRangeCatalog`). A published range gives a High-confidence match. When no range matches, a known provider network (ASN) gives a Medium one. Refresh the data with:

```powershell
./Scripts/Update-HostingRanges.ps1
```

Akamai publishes only its origin ACL ranges, so most Akamai edge addresses match by network rather than by range.

## CT from DDCT

The CT timeline queries `CertificateTransparencyTimelineAnalysis.Provider` first when it is set. When it isn't set and `DOMAINDETECTIVE_DDCT_URL` is, the timeline uses a `DdctApiCertificateTransparencyProvider` for that endpoint. `DOMAINDETECTIVE_DDCT_API_KEY` and `DOMAINDETECTIVE_DDCT_SCOPE` are optional. If the provider fails, the timeline falls back to crt.sh and records why (`ProviderFailureReason`). A DDCT first-seen date is the earliest entry DDCT has ingested, which can be later than the first certificate, so the profile shows it as the earliest entry returned and doesn't score it. DDCT holds only the names it monitors, so an empty DDCT answer is followed by a crt.sh query. Issuance dates use the first CT observation of each certificate, not a later re-observation.

## Not covered yet

- **GeoIP:** needs a licensed data source. See [IP_ENRICHMENT_FREE_GEOIP_OPTIONS.MD](IP_ENRICHMENT_FREE_GEOIP_OPTIONS.MD).
- **Passive DNS history and website change tracking:** both need records kept over time, which belongs in DomainDetectiveNext. The History area exists in the profile and stays "not available" until a source feeds it.
- **CT coverage:** DDCT doesn't report how far back its archive ingestion reaches yet, so first-seen coverage can't be confirmed.
