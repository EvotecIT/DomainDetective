# Domain risk profile

Status: design. Nothing here is implemented yet.

## Purpose

DomainDetective already collects most of what an analyst looks at when sizing up an unfamiliar domain: DNS, DNSSEC and PTR, ASN and CIDR, WHOIS and RDAP, CT history, threat feeds and DNSBL, web technologies and CDN hints. Each of these lands in its own check. Nothing puts them side by side and answers the two questions people actually ask:

1. **How risky does this domain look?**
2. **How sure are we?**

The assessment score answers a different question: how well the domain is configured (mail authentication, DNSSEC, TLS, headers). A domain registered yesterday on a fresh registrar, with a valid certificate and a perfect DMARC record, can earn an A for posture and still be a phishing domain. This design adds a **risk profile**: one model that combines the signals DD already has into a risk score with a separate confidence value, shown in the assessment report and in every export.

The rule that shapes everything below: **missing evidence lowers confidence, never the risk score.** A risk score only counts what was observed. When a source wasn't queried or failed, the profile says so and confidence drops, instead of pretending the domain is clean or punishing it for a lookup that timed out.

## Naming

The HTML report already has a "domain profile": the per-domain panels in `AssessmentHtmlReport.Profile.cs` (mail flow, DNS foundation, web front door, reputation). This feature is called the **risk profile** (`DomainRiskProfile`) so the two don't collide. In the HTML it becomes the first panel of that existing profile area.

## What exists today

### Inputs

| Input | Where | What the profile reads | How "not run" or "failed" shows today |
| --- | --- | --- | --- |
| DNS inventory | `DnsInventoryAnalysis` | `Provider`, `MailProvider`, `CnameTargetProvider`, `RecordTypesFailed`, per-type `DnsInventoryQueryStatus` | `QuerySucceeded`/`FailureReason`; a partial query doesn't set `Status = "Incomplete"` |
| DNSSEC | `DnsSecAnalysis` | `ValidationStatus` (`Secure`, `Insecure`, `Bogus`, `Indeterminate`, `NotChecked`), `KeyExpiresSoon` | `Indeterminate` already counts as incomplete evidence |
| PTR | `ReverseDnsAnalysis`, `IpEnrichmentRow.Ptr` | `PtrRecord`, `FcrDnsValid` per address | Only a null `PtrRecord`; no per-row error |
| IP enrichment | `IpEnrichmentAnalysis` | `Rows` (`Asn`, `AsName`, `Cidr`, `Country`), `DistinctAsnCount`, `DistinctCountryCount` | `QuerySucceeded`; per-IP RDAP success is internal |
| WHOIS | `WhoisAnalysis` | `Registrar`, `CreationDate`, `ExpiryDate`, `IsExpired`, `RegistrarLocked`, `PrivacyProtected` | Only a `WhoisCodes.QueryFailed` assessment; `WhoisInfo` drops `CreationDate` |
| RDAP | `RdapAnalysis` | `CreationDate`, `ExpiryDate`, `StatusValues`, `HasHoldStatus`, `EventSummaries` | `RecordAvailable == false` |
| CT timeline | `CertificateTransparencyTimelineAnalysis` | `FirstSeenUtc`, `LastSeenUtc`, `IssuerCounts`, `IssuedLast7Days`, `IssuedLast30Days`, `WildcardCertificateCount` | `QuerySucceeded`, `ResultsCapped`; queries crt.sh/CertSpotter directly |
| DDCT | `DdctApiCertificateTransparencyProvider` | `CtCertificateRecord.EntryTimestampUtc`, issuers, names | Not wired into any health check yet |
| Threat intel | `ThreatIntelAnalysis` (`ThreatIntelSource` feeds) | `Listings`, `CompositeScore`, `Confidence`, `Severity` | **Not queried and clean look the same**: GSB, PhishTank, VirusTotal and URLhaus are always added with `IsListed = false` |
| DNSBL | `DNSBLAnalysis` | `HostsListed`, `ProvidersWithListings`, per-record `QuerySucceeded` | `Status = "Incomplete"` on failed providers (the best-modelled partial state in DD) |
| Technologies and CDN | `TechSignatureCatalog` through `WebStaticScanAnalysis` | `TechDetails`, `StaticHost.EdgeProvider`, `StaticHost.Asn` | No `HealthCheckType`; the view reports itself as `HTTP`; `AnalysisComplete` isn't read |
| Web static scan | `WebStaticScanAnalysis` | `Hosts`, `TrackersUsed`, `BrokenResources`, `PrimaryRegistrableDomain` | As above |

### Scores and confidence already in DD

| Existing piece | What it measures | Scale | What the profile does with it |
| --- | --- | --- | --- |
| Assessment score and grade (`DomainAssessmentCatalog.CombinedScore`, `GradeFor`) | Configuration posture | 0–100, A–F; null when any scored check is incomplete | Kept separate and shown next to the risk score. Not folded in. |
| Legacy `DomainSecurityReport` | Mail and DNS posture | 0–100, four categories | Already removed. `SecurityScore`, `SecurityRiskLevel` and `IssueSeverity` in `DomainDetective.Reports/Models` have no consumer left; the implementation PR deletes them rather than reusing them. |
| `TyposquattingCandidateScorer` | How likely a lookalike is hostile | 0–100, None/Low/Medium/High/Critical (`>=75`, `>=55`, `>=30`, `>0`) | Same bands for the risk profile. The registration-age and threat-listing points move into shared signal rules that both scorers call. |
| `CertificateInventoryRiskAnalyzer` | Operational certificate risk per endpoint | 0–100, string severity (`>=85`, `>=60`, `>=30`, `>0`) | Counts of High and Critical endpoints feed the certificate facet at a low weight. Its `CtNotObserved` reason is reused. |
| `ThreatIntelAnalysis.CompositeScore` and `Confidence` | Feed listings with recency decay | 0–100 and 0–1 | Reused as the reputation facet's main input once per-source state exists (prerequisite P1). |
| `EndpointAttributionConfidence` | How sure an endpoint belongs to a provider | None/Low/Medium/High from a 0–1 sum (`>=0.75`, `>=0.5`) | The confidence pattern: a 0–1 value, the same three thresholds, and the evidence list behind it. |
| `MailDomainClassificationConfidence`, `Microsoft365DetectionConfidence` | Classification certainty | Ordinal | Unchanged. Shown as facts where useful. |

## The model

The profile lives in the core library (`DomainDetective/Profiles/`), built from typed analyses, so the CLI, PowerShell and JSON get the same thing the reports do. A view (`DomainRiskProfileInfo`, `Subject` = the domain) carries it into the assessment, and `DomainAssessmentBuilder` lifts that view into a new `DomainAssessment.RiskProfile` property instead of turning it into a check. Every renderer reads `DomainAssessment.RiskProfile`; none of them recompute anything.

```csharp
public sealed class DomainRiskProfile {
    public string Domain { get; init; }
    public DateTimeOffset EvaluatedAtUtc { get; init; }
    public string RuleVersion { get; init; }                 // e.g. "2027.1"; scores are only comparable within one version

    public int RiskScore { get; init; }                      // 0–100, observed risk only
    public DomainRiskLevel RiskLevel { get; init; }          // None, Low, Medium, High, Critical
    public bool Rated { get; init; }                          // false when confidence is below the rating floor

    public double ConfidenceScore { get; init; }             // 0–1
    public EvidenceConfidence Confidence { get; init; }      // Low, Medium, High

    public int? PostureScore { get; init; }                  // the assessment score, copied for display
    public string PostureGrade { get; init; }

    public List<RiskSignal> Signals { get; init; }           // everything that moved the score, ordered by points
    public List<ProfileFacet> Facets { get; init; }          // Registration, Dns, Network, Certificates, Reputation, Web, History
    public List<EvidenceGap> Gaps { get; init; }             // what would raise confidence, ordered by gain
}

public sealed class ProfileFacet {
    public ProfileFacetKind Kind { get; init; }
    public bool Core { get; init; }                          // core facets always count toward confidence
    public double Weight { get; init; }                      // share of confidence
    public double Coverage { get; init; }                    // 0–1
    public int RiskPoints { get; init; }                     // after the facet cap
    public List<EvidenceItem> Evidence { get; init; }
    public List<ProfileFact> Facts { get; init; }            // registrar, age, ASN, issuers, CDN...: shown, not scored
}

public sealed class EvidenceItem {
    public string Id { get; init; }                          // "registration.created", "reputation.gsb", ...
    public string Label { get; init; }
    public EvidenceState State { get; init; }
    public string? Source { get; init; }                     // "RDAP", "WHOIS", "crt.sh", "DDCT", "Google Safe Browsing"...
    public string? CheckKey { get; init; }                   // links to the assessment check that holds the evidence
    public DateTimeOffset? ObservedAtUtc { get; init; }
    public string? Note { get; init; }                       // "first seen on or before", "registration country"...
}

public enum EvidenceState {
    Observed,        // a value was returned
    Clean,           // the source answered and found nothing (a negative result is still evidence)
    Partial,         // some of it came back, e.g. 4 of 6 blocklists answered
    Failed,          // queried, but the source errored or timed out
    NotQueried,      // not requested, no API key, or the check wasn't selected
    NotAvailable     // no source exists for this yet (passive DNS today)
}

public sealed class RiskSignal {
    public string Id { get; init; }                          // stable: "registration.age.under30d"
    public ProfileFacetKind Facet { get; init; }
    public int Points { get; init; }                         // positive raises risk, negative is a trust signal
    public bool Decisive { get; init; }                      // sets a floor on the level
    public string Reason { get; init; }                      // shared wording
    public List<string> EvidenceIds { get; init; }
}

public sealed class EvidenceGap {
    public string EvidenceId { get; init; }
    public EvidenceState State { get; init; }
    public double ConfidenceGain { get; init; }              // how much confidence would rise if it were observed
    public string Action { get; init; }                      // "Add a VirusTotal API key", "RDAP timed out; run again"
}
```

`EvidenceConfidence` is a new enum with the same members and thresholds as `EndpointAttributionConfidence`. I'm not reusing that enum directly because it's public API with a specific meaning (endpoint ownership); both stay, with the thresholds in one shared helper.

## The facets and the evidence each one needs

Core facets always count toward confidence. Optional facets count only when their source is configured, so a profile without a web scan or passive DNS can still reach High confidence; when they are configured and fail, they count like core facets.

| Facet | Core | Confidence weight | Evidence items | Scored signals | Facts only (never scored) |
| --- | --- | --- | --- | --- | --- |
| Reputation | yes | 0.30 | One item per threat feed (GSB, PhishTank, OpenPhish, URLhaus, VirusTotal), DNSBL for the domain, DNSBL for mail and web hosts | Feed listings, VirusTotal reputation, domain DNSBL listing, host DNSBL listings | Feeds checked, last listing date |
| Registration | yes | 0.20 | Creation date (RDAP first, WHOIS second), expiry date, status codes, registrar | Age, hold status, expired, short remaining term | Registrar, privacy service, registrant type, transfer lock |
| Certificates | yes | 0.15 | CT first seen, CT last seen, issuer list, issuance velocity, live certificate inventory | Recent first issuance, issuance burst, no CT history for a served certificate, High/Critical inventory endpoints | Issuers, wildcard count, CT source and its coverage |
| DNS | yes | 0.15 | Inventory query status, DNSSEC status, NS, MX, PTR for mail hosts | DNSSEC `Bogus`, address churn across ASNs with short TTLs, mail hosts without FCrDNS | DNS provider, mail provider, DNSSEC `Secure` |
| Network | yes | 0.10 | ASN and CIDR per address, country with its source, hosting/CDN attribution | Mail served from residential/dynamic ranges (PTR pattern) | ASNs, countries, CDN, hosting provider |
| Web | optional | 0.10 | Web static scan, technology detections | Parking-page technology, credential form on a domain under 30 days old | Technologies, CDN from headers, trackers |
| History | optional | 0.10 | Passive DNS (later, see Gaps) | Recent NS or address change, very short hosting history | First resolution date, hosting changes |

Two deliberate choices in that table:

- **Country is never a risk signal by default.** It's context. Penalising a country would bake a bias into every report. An organisation that wants that rule expresses it as a desired-state baseline, where it shows as a policy result, not a risk.
- **WHOIS privacy is not a risk signal.** Most legitimate registrations use it now. It's shown as a fact.

## How the risk score is computed

The score is additive, like the typosquatting and certificate scorers, so every point has a reason the reader can see.

1. Each rule looks at evidence items in state `Observed` (or `Clean` where a negative result means something, such as "DNSSEC secure") and emits `RiskSignal`s.
2. Signals are summed per facet and clamped to the facet cap, so one noisy facet can't carry the score on its own.
3. Facet totals are summed. Trust signals (negative points) are summed separately and can lower the total by at most 20.
4. The total is clamped to 0–100.
5. Decisive signals set a floor on the level: a live listing on a phishing or malware feed means at least High (55), whatever else was found.
6. The level uses the typosquatting bands: `>=75` Critical, `>=55` High, `>=30` Medium, `>0` Low, `0` None.

Starting rule set (version `2027.1`). Points are a first calibration and will move once there's a labelled corpus (see Open questions).

| Facet (cap) | Signal | Points | Evidence it needs |
| --- | --- | --- | --- |
| Reputation (60) | Listed on GSB, PhishTank, OpenPhish or URLhaus within the recency window | +40 first, +10 each further feed; decisive | Per-feed state `Observed` |
| | VirusTotal reputation | `ThreatIntelAnalysis` VirusTotal component, scaled to at most +20 | VirusTotal `Observed` |
| | Domain on a domain blocklist (DNSBL) | +20 | Domain DNSBL `Observed` |
| | Mail or web host address listed | +5 per host, at most +15 | Host DNSBL `Observed` |
| Registration (30) | Registered under 30 days ago | +20 | Creation date |
| | Registered 30–90 days ago | +12 | Creation date |
| | Registered 90–365 days ago | +5 | Creation date |
| | `clientHold` or `serverHold` | +20 | RDAP status |
| | Expired | +15 | Expiry date |
| | Registered over 3 years ago | −5 (trust) | Creation date |
| Certificates (20) | First CT entry under 30 days ago | +8 | CT first seen with coverage (see DDCT gap) |
| | Issuance burst: 7-day issuance over 5 and over 4× the 90-day weekly mean | +5 | CT velocity |
| | Served certificate never seen in CT | +5 (`CtNotObserved`) | Certificate inventory and CT |
| | Inventory endpoint at High or Critical | +5, at most +10 | `CertificateInventoryRiskAnalyzer` |
| DNS (15) | DNSSEC `Bogus` | +10 | DNSSEC status |
| | Apex addresses across 3+ ASNs with TTL under 300 s | +10 | Inventory, IP enrichment |
| | Mail hosts without forward-confirmed reverse DNS | +3 | PTR |
| | DNSSEC `Secure` | −3 (trust) | DNSSEC status |
| Network (10) | Mail host PTR looks residential or dynamic | +5 | PTR, IP enrichment |
| Web (15) | Parking-page technology detected | +5 | Technology detections |
| | Password field on a domain registered under 30 days ago | +10 | Web static scan, creation date |
| History (15) | NS or apex address changed in the last 7 days | +8 | Passive DNS |
| | Under 30 days of resolution history | +7 | Passive DNS |

### Posture stays out of the score

Weak DMARC makes a domain easier to spoof, which is a risk to everyone who receives its mail. It's still a posture finding with its own check, grade and fix. Counting it again in the risk score would double-count it and would make the risk score move every time someone fixes SPF. The profile shows the posture grade next to the risk level and leaves it there.

### Lookalikes are exposure, not risk

`TyposquattingAnalysis` finds domains that imitate this one. Those are a threat *to* the domain owner, not evidence that the domain itself is hostile. When typosquatting ran, the profile lists the count of High and Critical lookalikes as a fact ("Lookalikes: 3 high risk") with a link to the check. It doesn't add points.

Going the other way, profiling a lookalike candidate is exactly what `TyposquattingCandidateScorer` does with its own similarity signals. The shared signal rules (age, threat listing, hold status) move into one place that both call, so a domain registered 12 days ago gets the same reason text and the same points in both reports.

## How confidence is computed

Confidence answers "how much of what we'd want to know did we actually see". It follows the `EndpointAttributionConfidence` pattern: a 0–1 value from weighted evidence, three levels, and the evidence list behind it.

1. **Item value.** Each evidence item gets a value from its state: `Observed` and `Clean` 1.0, `Partial` 0.5, `Failed`, `NotQueried` and `NotAvailable` 0.
2. **Freshness.** Time-sensitive items (threat feeds, DNSBL, CT last seen, passive DNS) older than 30 days count at half value. Registration dates don't decay.
3. **Facet coverage.** The mean item value within the facet, with the facet's own item weights (in the reputation facet, GSB and VirusTotal count more than a single DNSBL zone).
4. **Base confidence.** `Σ(weight × coverage) / Σ(weight)` over core facets plus configured optional facets.
5. **Corroboration.** For a Medium, High or Critical level, take away each source's signals in turn. If the level holds every time, the level is corroborated: add 0.10. If removing one source drops the level, the level rests on that source alone: cap confidence at 0.74 (Medium) and say which source it rests on.
6. **Level.** `>=0.75` High, `>=0.50` Medium, otherwise Low.
7. **Rating floor.** Below 0.25, the profile is `Rated = false`: it shows "Not rated: too little evidence" and the list of gaps, with no level.

`EvidenceGap.ConfidenceGain` is the difference step 4 would make if that item were `Observed`. Gaps are listed largest gain first, each with the action that would close it ("Add a Google Safe Browsing API key", "RDAP timed out; run again", "Configure a DDCT endpoint").

### Why missing data doesn't touch the score

The assessment's `CombinedScore` returns null when any scored check is incomplete. That is right for posture: a half-checked SPF record shouldn't earn a number. A risk score has a different job. It reports what was observed, and the useful answer for a half-checked domain is "this much risk found so far, with low confidence", not no answer at all.

So the profile treats the two axes separately:

- A source that wasn't queried or failed contributes **no points** and **lowers confidence**.
- A source that answered and found nothing is `Clean`. It also contributes no points, but it **raises confidence**. This is why prerequisite P1 matters: today an unqueried feed and a clean feed look identical, which would inflate confidence.
- The wording never turns absence into safety. With Low confidence, a score of 0 reads "No risk signals found in the evidence collected", never "Safe" or "No risk".

Example with made-up data:

| | Domain A | Domain B |
| --- | --- | --- |
| Evidence | Everything answered, nothing found; country from RDAP registration only | RDAP and WHOIS timed out, no threat feeds queried, CT query failed, DNSBL clean |
| Risk score | 0, None | 0, None |
| Confidence | 0.97, High | 0.33, Low |
| Shown as | "No risk signals found · High confidence" | "No risk signals found in the evidence collected · Low confidence", followed by the three biggest gaps |

## Prerequisites in existing analyses

These are small, independently useful fixes that the engine needs to be honest. Each ships on its own.

| # | Change | Why the profile needs it |
| --- | --- | --- |
| P1 | `ThreatIntelAnalysis` records a state per source: `Listed`, `Clean`, `NotQueried`, `Failed` (`ThreatIntelFinding` gets a state; `ThreatListing` in the view follows) | Without it, unqueried feeds count as clean and inflate confidence |
| P2 | `WhoisInfo` and `RdapInfo` expose a parsed `CreatedUtc` and `ExpiresUtc` (`DateTimeOffset?`) beside the strings | Domain age is the strongest registration signal and today needs `Raw` |
| P3 | `IpEnrichmentRow` gets `CountrySource` (`RdapRegistration`, `GeoIp`, ...) | Today's `Country` is the RDAP registration country, not where the server is; the profile must say which |
| P4 | Analyses with `QuerySucceeded = false` or `RecordTypesFailed > 0` (DNS inventory, IP enrichment, CT timeline) set `Status = "Incomplete"` | So the assessment and the profile agree on partial evidence |
| P5 | `WebStaticScanAnalysis` gets its own check key instead of reporting as `HTTP`, and the converter reads `AnalysisComplete` | Its CDN attribution is the only one DD has, and a partial scan must read as partial |
| P6 | `CertificateTransparencyTimelineAnalysis` queries through `ICtCertificateTransparencyProvider` | So DDCT (and crt.sh SQL) can supply CT history, with its coverage |

## Where it shows

All text comes from a new `RiskProfile` region in `AssessmentReportWording`: level names, "Not rated", the reason text per signal ID, gap actions and the no-signal sentences. Every renderer follows `Docs/REPORT_EXPORTS.MD` §0: incomplete or missing evidence is neutral grey, never amber; zero is muted, not green.

The mock-up is in [Docs/mockups/domain-risk-profile.html](mockups/domain-risk-profile.html).

### HTML (`DomainDetective.Reports.Html/Assessment`)

- **Per domain**, in `AssessmentHtmlReport.Profile.cs`: a new first panel in `RenderDomainProfile`, titled "How risky is {domain}?", above the mail flow. Built with the existing HtmlForgeX parts:
  - `AssessmentStats`: risk level and score, confidence level and value, posture grade (linking to the area scores).
  - "Why": the signals as assertions, with points and the source, each linking to the check that holds the evidence.
  - A facet strip (`AssessmentChips`): one chip per facet with its coverage; grey for missing or partial, never amber.
  - "What would raise confidence": the top three gaps with their actions.
  - Facts as a compact two-column list: registrar and age, hosting and CDN, ASNs and countries (with "registration country" when that's the source), CT issuers and first seen.
- **Summary** (several domains): a "Risk" column in the coverage table with level and confidence, sortable, so the riskiest domains rise to the top. "Do these first" is unchanged; it stays about fixes.
- **About**: the rule version, the band thresholds and a line on how confidence works.

### Word and PDF (`DomainDetective.Reports.Office`)

- **Domain chapter**, right after the per-area metric strip: a "Risk profile" block.
  - A value-card strip: Risk (level and score, or "Not rated" muted), Confidence, Posture grade.
  - A two-column table like "Do these first": points in the narrow left column, reason and source on the right.
  - A facet table: Facet, Coverage, Evidence (for example "4 of 5 feeds answered"), with grey state words for missing evidence.
  - "What would raise confidence": the gaps as a short list.
- **Summary** (several domains): Risk and Confidence columns in the area-by-area table's domain rows.
- **Cover**: unchanged. The four cards stay about posture.
- **Appendix**: the full evidence item list per domain (Facet, Evidence, State, Source, Observed).

### Excel

Three new sheets:

- **Risk profile**: one row per domain: Domain, Risk score, Risk level, Rated, Confidence, Confidence score, Posture grade, Top signals.
- **Risk signals**: one row per signal: Domain, Facet, Signal ID, Reason, Points, Decisive, Source, Evidence IDs.
- **Evidence coverage**: one row per domain and evidence item: Facet, Evidence, State, Source, Observed (UTC), Check key, Confidence gain.

### Markdown

Under each domain heading, before the checks table:

```markdown
### Risk profile

**High risk (68) · Medium confidence (0.74).** The level rests on Google Safe Browsing alone. Posture grade B.

| Points | Why | Source |
| ---: | --- | --- |
| +40 | Listed by Google Safe Browsing (social engineering), 2 days ago | Threat intel |
| +20 | Registered 12 days ago | WHOIS |
| +8 | First certificate logged on or before 11 days ago | CT (DDCT) |

| Facet | Coverage | Evidence |
| --- | --- | --- |
| Reputation | 80% | 4 of 5 feeds answered; VirusTotal not queried (no API key) |
| Registration | 80% | WHOIS; RDAP timed out, so no status codes |
| Certificates | 80% | DDCT; archive ingestion incomplete for 2 logs |
| DNS | 100% | Inventory, DNSSEC, PTR |
| Network | 75% | ASN and CIDR; country is the registration country |
| Web, History | n/a | Web scan not run; passive DNS not configured |

What would raise confidence: add a VirusTotal API key (+0.07); run again for RDAP status (+0.04).
```

The numbers in this example are worked through in the mock-up.

### JSON

`DomainAssessment.RiskProfile` serializes with the rest of the assessment through `DomainAssessmentJson`. Signal and evidence IDs are stable strings so DomainDetectiveNext and other consumers can key on them.

## Gaps that feed it later

Each of these lands in a facet that already exists in the model, so adding one raises confidence and enables its signals without changing the renderers.

### Passive DNS history (DomainDetectiveNext)

DomainDetectiveNext owns passive DNS collection. DD only consumes it.

- **Contract in DD:** `IPassiveDnsSource` with `QueryAsync(name, since, ct)` returning records of `RrName`, `RrType`, `RData`, `FirstSeenUtc`, `LastSeenUtc`, `Count`, `Source`, plus a coverage statement (how far back the source has data for this name). The shape follows `ICtCertificateTransparencyProvider` and its profiles, so a source declares its capabilities and limits.
- **Feeds:** the History facet: first resolution date, NS and address changes in the last 7 and 30 days, distinct hosting ASNs over 90 days.
- **Until then:** History is an optional facet in state `NotAvailable`. It doesn't lower confidence unless a source is configured. `IPNeighborAnalysis`'s HackerTarget reverse-IP lookup is not passive DNS history and doesn't feed this facet.

### GeoIP and hosting/CDN attribution by IP range (DD)

DD owns this. The plan in [IP_ENRICHMENT_FREE_GEOIP_OPTIONS.MD](IP_ENRICHMENT_FREE_GEOIP_OPTIONS.MD) (range-aware `GeoIpAnalysis`, an external database path, provenance per row) is the GeoIP half.

- **Hosting and CDN:** published ranges (AWS `ip-ranges.json`, Azure service tags, Google Cloud, Cloudflare, Fastly, Akamai) as IP-prefix rules in the endpoint attribution rule packs, which already handle Azure service tags. Each address then gets a provider with an `EndpointAttributionConfidence`, instead of only the web scan's `EdgeProvider` heuristics.
- **Feeds:** the Network facet's country (with `CountrySource = GeoIp`) and hosting provider. It also enables a future "hosted on a range with a poor abuse record" signal once there's a data source for it.
- **Until then:** country is shown as "registration country (RDAP)", hosting comes from `WebStaticScanAnalysis.EdgeProvider` or AS-name matching when the web scan ran, and those items count as `Partial`.

### CT first seen (DDCT)

DDCT owns this. It already stores `certificate_name_observations.first_seen_utc`, but that is the first time DDCT recorded the name, which depends on how far its archive ingestion has reached for each log. A first-seen date is only meaningful with that coverage next to it.

- **Needed from DDCT:** a search route returning the earliest observation for a name (with or without subdomains) together with the coverage it rests on: per CT log, the earliest entry timestamp ingested and whether archive ingestion for that log is complete.
- **In DD:** `DdctApiCertificateTransparencyProvider` reads it (through P6). When coverage is complete for the logs that matter, first seen is `Observed`. When it isn't, the profile shows "first seen on or before {date}" and counts the item as `Partial`. crt.sh stays the fallback.
- **Feeds:** the "first CT entry under 30 days ago" signal, and a newness check for TLDs whose RDAP doesn't publish a creation date.

## Delivery order

1. P1–P6, each as its own change with its own tests.
2. The model, rules and builder in the core library, with JSON. Contract tests on made-up data:
   - a missing source lowers confidence and leaves the score unchanged;
   - a clean source raises confidence and leaves the score unchanged;
   - a decisive signal holds the floor regardless of trust signals;
   - trust signals never lower the total by more than 20;
   - below the rating floor, nothing renders a level.
3. The HTML panel and summary column.
4. Word/PDF, Excel and Markdown, with one parity test that every renderer prints the same level, confidence and reason text for one fixture.
5. The three feeds as they become available.

## Open questions

- **Calibration.** The points and caps above are a starting point. They need a labelled set (known-bad from feeds, known-good long-lived domains, fresh but legitimate registrations) to tune against, kept outside the repository with only the resulting rule version recorded here.
- **Recency window for feed listings.** `ThreatIntelAnalysis` already decays by age; the decisive floor needs its own cut-off (30 days is the proposal).
- **PowerShell surface.** Whether the profile gets its own cmdlet (`Get-DDDomainRiskProfile`) or stays a property of the assessment result.
