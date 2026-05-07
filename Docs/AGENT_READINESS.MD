# Agent Readiness Assessment

## Purpose

This note assesses what DomainDetective would need to add to evaluate whether a website is ready for AI crawlers and AI agents in the same practical space as:

- Cloudflare's agent readiness scanner: https://isitagentready.com/
- IsAgentReady: https://isagentready.com/en/

The goal should not be to clone either scoring model exactly. The useful DomainDetective feature is a reproducible, evidence-first website assessment that maps emerging agent-facing standards to concrete checks, recommendations, report sections, and desired-state controls.

## External Scanner Model

Cloudflare describes its scanner as checking agent standards across discoverability, content, bot access control, capabilities, and commerce. Its public blog names these concrete checks: `robots.txt`, `sitemap.xml`, RFC 8288 Link headers, Markdown for Agents, Content Signals, AI bot rules in `robots.txt`, Web Bot Auth, Agent Skills, RFC 9727 API Catalog, RFC 8414 OAuth authorization server discovery, RFC 9728 OAuth protected resource metadata, MCP Server Card, and WebMCP. It also checks x402, UCP, and ACP, but says commerce checks do not currently count toward the score.

IsAgentReady uses a broader SEO/content-readiness rubric. Its published model uses five weighted categories: AI Content Discovery at 30%, AI Search Signals at 20%, Content & Semantics at 20%, Agent Protocols at 15%, and Security & Trust at 15%. It explicitly tests raw HTML without JavaScript, individual AI bot directives, structured data, semantic HTML, WebMCP, A2A Agent Cards, MCP discovery, OpenAPI, `agents.json`, HTTPS, HSTS, CSP, CORS, and related security headers.

DomainDetective should support both views by exposing raw check evidence and one or more score profiles:

| Profile | Purpose | Notes |
| --- | --- | --- |
| `CloudflareLike` | Track standards Cloudflare's scanner publicly names. | Useful for site owners trying to improve `isitagentready.com` posture. |
| `SeoAgentReadiness` | Track IsAgentReady-style search, semantic HTML, and trust signals. | Includes more content and accessibility checks than Cloudflare's score. |
| `DomainDetectiveDefault` | Stable DD-owned posture score. | Should avoid overweighting very early commerce or protocol experiments. |

## Standards And Protocols To Track

| Area | Check | Standard or source | DD status today |
| --- | --- | --- | --- |
| Discoverability | `robots.txt` availability and parseability | RFC 9309 | Partially covered by `RobotsTxtAnalysis`. |
| Discoverability | `Sitemap:` declarations in `robots.txt` plus sitemap fetch | Sitemaps.org convention | Partially covered by robots and `WebStaticScanAnalysis.RobotsSitemaps`; no sitemap XML validation yet. |
| Discoverability | RFC 8288 Link header relations | RFC 8288 | Partially captured as raw Link on static requests; no relation parser or agent-specific relation checks. |
| Discoverability | `llms.txt` and optional `llms-full.txt` | Emerging convention, not an RFC | Missing as first-class check. |
| Content access | `Accept: text/markdown` negotiation | HTTP content negotiation plus Cloudflare Markdown for Agents practice | `HttpRequestOptions` can send headers, but DD does not compare HTML and Markdown variants as a named check. |
| Bot access | AI crawler user-agent groups | RFC 9309 plus provider-specific bot names | Partially covered for a small bot set; needs expanded catalog and allow/disallow outcome model. |
| Bot access | `Content-Signal` in `robots.txt` and response headers | Cloudflare Content Signals policy | Missing structured parser; current robots parser stores it as an unknown directive. |
| Search signals | JSON-LD and Schema.org type inventory | Schema.org JSON-LD practice | Partially counted by `WebStaticScanAnalysis.StructuredDataTypes`; needs validation and high-value type mapping. |
| Semantics | SSR/raw HTML content, heading hierarchy, language, landmarks, alt text, link text | HTML/accessibility best practices | Mostly missing; some data can come from the captured main body. |
| Protocol discovery | RFC 9727 API Catalog at `/.well-known/api-catalog` and Link relation `api-catalog` | RFC 9727 | Missing as first-class check. |
| Protocol discovery | OAuth authorization server metadata | RFC 8414 | Missing for website/API readiness. |
| Protocol discovery | OAuth protected resource metadata | RFC 9728 | Missing. |
| Protocol discovery | Agent Skills index and `SKILL.md` resources | Agent Skills emerging spec | Missing. |
| Protocol discovery | A2A Agent Card | A2A emerging spec | Missing. |
| Protocol discovery | MCP Server Card and MCP endpoint hints | MCP emerging spec | Missing. |
| Protocol discovery | WebMCP declarations | WebMCP emerging spec | Missing. |
| Protocol discovery | `agents.json` | Emerging convention | Missing. |
| Commerce | x402, UCP, ACP, MPP indicators | Emerging commerce protocols | Missing; should be optional and low-weight initially. |
| Trust | HTTPS, HSTS, CSP, X-Content-Type-Options, X-Frame-Options, CORS, Referrer-Policy | HTTP/security header practice | Covered by `HttpAnalysis` and `WebStaticScanAnalysis`, but not rolled into an agent-readiness view. |

## Current DomainDetective Fit

The implementation should reuse the current website stack rather than adding a parallel crawler:

| Existing surface | Reuse | Gap |
| --- | --- | --- |
| `DomainDetective.Protocols.RobotsTxtAnalysis` | Fetches/parses `robots.txt`, detects some AI bot directives, collects sitemap declarations. | Add a bot catalog, effective allow/disallow outcome per bot, content-signal parsing, RFC 9309 warnings, and explicit sitemap validation. |
| `DomainDetective.Protocols.Robots.RobotsTxtParser` | Simple parser for groups, directives, and sitemaps. | Preserve unknown directives today, but add typed support for `Content-Signal` without breaking unknown handling. |
| `DomainDetective.Protocols.HttpAnalysis` | Fetches main page, follows redirects, captures body, supports custom request headers, validates security headers. | Add reusable response metadata needed by agent checks: content type, `Vary`, Link headers, content-signal header, and all response headers or a selected agent header set. |
| `DomainDetective.Protocols.WebStaticScanAnalysis` | Captures raw HTML, JSON-LD type counts, link hints, resources, first/third party posture, header frequency, robots sitemaps. | Add a lightweight page semantics pass and expose structured data validation details, not just type counts. |
| `DomainDetective.Views.Converters.*` | Converts analyses to view models and report evidence. | Needs `AgentReadinessInfo` with categories, checks, score, evidence URLs, and recommendations. |
| `DomainDetective.Diagnostics.Recommendations` | Central recommendation mapping by assessment code. | Add `AgentReadinessCodes` and recommendation catalog entries. |
| `DomainDetective.Definitions.HealthCheckType` | First-class check routing. | Add `AGENTREADINESS` or `AGENTREADY`; prefer `AGENTREADINESS` for clarity. |
| `DomainDetective.CLI` and `DomainDetective.PowerShell` | Existing command/check export surfaces. | Add CLI command/check routing and PowerShell cmdlet surface after the library analysis exists. |

## Recommended Design

Add a new first-class analysis rather than stretching `HTTP`:

- `DomainDetective.Protocols.AgentReadinessAnalysis`
- `DomainDetective.Protocols.AgentReadinessOptions`
- `DomainDetective.Protocols.AgentReadinessResult` or direct properties on the analysis class, matching current DD style
- `DomainDetective.Diagnostics.Codes.AgentReadinessCodes`
- `DomainDetective.Diagnostics.Recommendations.AgentReadinessRecommendations`
- `DomainDetective.Narratives.AgentReadinessNarrative`
- `DomainDetective.Views.Converters.AgentReadiness`

The analysis should orchestrate existing `HttpAnalysis`, `RobotsTxtAnalysis`, and selected static scan helpers, then run agent-specific probes.

## Implementation Status

The current branch includes the first library and surface slice:

| Item | Status |
| --- | --- |
| `HealthCheckType.AGENTREADINESS` | Implemented. |
| `AgentReadinessAnalysis` | Implemented with robots, sitemap, `llms.txt`, Markdown, Link header, Content-Signal, API Catalog, Agent Skills, `agents.json`, OpenAPI, OAuth, A2A, MCP, HTTPS, and trust-header probes. |
| Link header parser | Implemented with quoted-comma and relative-target tests. |
| Endpoint shape validation | Implemented for RFC 9727 API Catalog, Agent Skills index, `agents.json`, and OpenAPI. |
| Assessments and recommendations | Implemented and included in aggregate `DomainHealthCheck` recommendations. |
| View conversion and narrative | Implemented through `AgentReadinessInfo` and `AgentReadinessNarrative`. |
| CLI/PowerShell routing | Implemented for check data, CLI summary, `Test-DDAgentReadiness`, and PowerShell composition item conversion. |
| Desired State | Implemented through `agentReadiness` policy and `New-DDDesiredStateAgentReadiness`. |
| Focused tests | Implemented with local `HttpListener` fixtures. |

Suggested model:

| Model | Fields |
| --- | --- |
| `AgentReadinessCheck` | `Id`, `Category`, `Name`, `Status`, `Score`, `MaxScore`, `Evidence`, `RecommendationCode`, `References`. |
| `AgentReadinessCategoryScore` | `Category`, `Score`, `MaxScore`, `Weight`, `Passed`, `Warnings`, `Failed`. |
| `AgentReadinessEndpointProbe` | `Url`, `StatusCode`, `ContentType`, `ValidJson`, `SchemaName`, `DiscoverySource`, `Error`. |
| `AgentReadinessLinkRelation` | `Relation`, `Target`, `Type`, `SourceUrl`, `ValidTarget`, `EndpointProbe`. |
| `AgentBotDirectiveResult` | `BotName`, `UserAgentToken`, `Purpose`, `MatchedGroup`, `AllowedRoot`, `DisallowedRoot`, `ContentSignalImpact`. |
| `ContentSignalPolicy` | `Search`, `AiInput`, `AiTrain`, `Source`, `RawValue`. |
| `MarkdownNegotiationResult` | `RequestedUrl`, `StatusCode`, `ContentType`, `VaryAccept`, `MarkdownBytes`, `HtmlBytes`, `TokenHint`, `AlternateLink`. |

## Probe Plan

An MVP probe run for `https://example.com/` should:

1. Normalize the input to an HTTPS origin and keep the final redirect target.
2. Fetch the main page as normal HTML using `HttpAnalysis` with body capture.
3. Fetch the same page with `Accept: text/markdown, text/html;q=0.8` and compare content type, `Vary`, status, and body.
4. Fetch `https://host/robots.txt`, parse RFC 9309 directives, sitemaps, AI user-agent groups, and `Content-Signal`.
5. Fetch `https://host/llms.txt`, optionally `llms-full.txt`, and validate status, content type, size, and useful links.
6. Parse response Link headers from the main page, `llms.txt`, and markdown variant using an RFC 8288-aware parser.
7. Probe well-known and linked discovery endpoints:
   - `/.well-known/api-catalog`
   - `/.well-known/oauth-authorization-server`
   - `/.well-known/oauth-protected-resource`
   - `/.well-known/agent-skills/index.json`
   - `/.well-known/skills/index.json`
   - `/.well-known/agent-card.json`
   - `/.well-known/agent.json`
   - `/.well-known/mcp-server`
   - `/.well-known/mcp.json`
   - `/agents.json`
   - `/openapi.json`
8. Validate JSON endpoint shape enough to classify it, without enforcing unstable draft schemas too tightly.
9. Run raw HTML content checks: title, meta description, canonical, language, main/headings, links with usable text, image alt coverage, JSON-LD types, and likely JavaScript-only shell detection.
10. Roll existing `HttpAnalysis` security header results into the trust category.

## Scoring

Use transparent score profiles rather than hard-coded scanner parity:

| Category | `DomainDetectiveDefault` weight | Notes |
| --- | ---: | --- |
| Discoverability | 25 | robots, sitemap, Link headers, `llms.txt`, `agents.json`. |
| Content accessibility | 20 | Markdown negotiation, raw HTML content, SSR, semantic hints. |
| Bot access policy | 15 | AI bot directives and Content Signals. |
| Protocol discovery | 20 | API Catalog, OAuth metadata, Agent Skills, A2A, MCP, WebMCP, OpenAPI. |
| Security and trust | 15 | HTTPS, HSTS, CSP, X-Content-Type-Options, X-Frame-Options, CORS, Referrer-Policy. |
| Commerce | 5 | x402/UCP/ACP/MPP; keep optional because most sites will not need this. |

For Cloudflare-like output, keep commerce as informational by default because Cloudflare says those checks do not currently count toward its score.

For IsAgentReady-like output, expose its public weighting:

| Category | Weight |
| --- | ---: |
| AI Content Discovery | 30 |
| AI Search Signals | 20 |
| Content & Semantics | 20 |
| Agent Protocols | 15 |
| Security & Trust | 15 |

## `evotec.xyz` Baseline On 2026-05-05

Manual spot checks from the worktree show `evotec.xyz` is already a strong fixture for DD tests and examples:

| Check | Observed result |
| --- | --- |
| `robots.txt` | Present, allows `*`, includes sitemap declarations, and has `Content-Signal: search=yes, ai-input=yes, ai-train=no`. |
| `llms.txt` | Present, `200`, `Content-Type: text/plain`, includes project/API pointers. |
| Markdown artifact | `/index.md` present, `200`, `Content-Type: text/markdown`. |
| Markdown negotiation | Main page with `Accept: text/markdown` returned `text/html`, but Link header advertised `/index.md` as `rel="alternate"; type="text/markdown"`. DD should distinguish direct negotiation from alternate markdown discovery. |
| Link headers | Present on main and `llms.txt`, including `rel="api-catalog"`, `rel="describedby"`, `rel="alternate"`, and `rel="service-doc"`. |
| API Catalog | `/.well-known/api-catalog` present, `200`, `application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"`. |
| Agent Skills | `/.well-known/agent-skills/index.json` present and points to a `SKILL.md`. |
| `agents.json` | Present, describes robots, sitemap, llms, API catalog, agent skills, and null MCP/A2A resources. |
| OAuth metadata | `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` returned `404`. |
| A2A/MCP well-known probes | `agent-card.json`, `agent.json`, `mcp-server`, and `mcp.json` returned `404`. |

This baseline is useful because it demonstrates why DD needs evidence granularity. A site can be highly agent-readable through `llms.txt`, Link headers, API Catalog, Agent Skills, and markdown alternates while still not exposing OAuth, A2A, or MCP endpoints.

## Implementation Slices

### Slice 1: Library MVP

- Add `HealthCheckType.AGENTREADINESS`.
- Add `AgentReadinessAnalysis` with option-controlled probes and no external browser dependency.
- Reuse `HttpAnalysis` and `RobotsTxtAnalysis`; add small helpers only where current public models do not expose needed evidence.
- Add RFC 8288 Link header parser helper and tests.
- Add `Content-Signal` parser and expanded AI bot catalog.
- Add endpoint probe model for well-known resources.
- Add assessments and recommendations for missing/invalid/present checks.

### Slice 2: Reports And Narratives

- Add converter/view model.
- Add narrative with highlights, problems, remediation priorities, and references.
- Add HTML, Markdown, Word, and Excel sections following existing report patterns.
- Add dashboard rollup columns: score, discoverability, markdown, bot policy, protocols, trust.

### Slice 3: CLI And PowerShell

- CLI: `--check AGENTREADINESS` is available through existing overall analysis output.
- PowerShell: `Test-DDAgentReadiness` provides a focused scan surface, and `AGENTREADINESS` is included in `Test-DDDomainOverallHealth`.
- Keep function/cmdlet docs aligned with repository guidance and XmlDoc2CmdletDoc.

### Slice 4: Desired State

Desired-state config supports optional requirements:

```json
{
  "agentReadiness": {
    "minimumScore": 70,
    "requireRobotsTxt": true,
    "requireSitemap": true,
    "requireLinkHeaders": true,
    "requireLlmsTxt": true,
    "requireMarkdown": true,
    "requireContentSignals": true,
    "requireAiBotRules": true,
    "requireApiCatalog": true,
    "requireAgentSkills": true,
    "requireAgentsJson": false,
    "requireOpenApi": false,
    "requireHttps": true,
    "minTrustHeaders": 3
  }
}
```

## Test Plan

Add unit tests with local HTTP listeners rather than public network dependencies:

| Test area | Cases |
| --- | --- |
| Robots policy | AI bot allow/disallow per group, wildcard fallback, content-signal parsing, sitemap extraction. |
| Link parser | Quoted commas, multiple relations, relative target resolution, `type` and `profile` attributes. |
| Markdown | Direct `Accept: text/markdown`, alternate Link only, `/index.md` fallback, missing `Vary: Accept`. |
| Well-known probes | 200 valid JSON, 200 invalid JSON, 404, redirect, wrong content type, linked target versus default location. |
| API Catalog | `application/linkset+json`, RFC 9727 profile, OpenAPI links. |
| Agent Skills | Valid index with `skills[]`, missing `digest`, relative `SKILL.md` URL resolution. |
| Content semantics | JSON-LD type extraction, missing title/description, heading gaps, image alt ratio, JS-only shell heuristic. |
| Scoring | Profile weights, informational checks, optional commerce checks, stable score output. |

## Risks And Open Questions

- Many agent protocols are still moving. Keep draft-specific validation shallow unless a stable schema is available.
- `llms.txt`, `agents.json`, Agent Skills, WebMCP, and A2A are not all IETF standards. DD should report source and maturity, not imply RFC status.
- Direct markdown negotiation and markdown alternate discovery should be separate checks. They are not equivalent operationally.
- Robots AI bot policy needs purpose-aware interpretation. Blocking `GPTBot` for training can be acceptable while allowing `ChatGPT-User` or `OAI-SearchBot` for user-initiated access can be desirable.
- Commerce readiness should be disabled or low-weight for ordinary content sites and more important for ecommerce/API profiles.
- Avoid a Chromium dependency in the core library. The scanners explicitly value raw HTML behavior; a browser-rendered mode can remain a future optional diagnostic.

## Source References

- Cloudflare agent readiness announcement: https://blog.cloudflare.com/agent-readiness/
- Cloudflare Markdown for Agents: https://developers.cloudflare.com/fundamentals/reference/markdown-for-agents/
- Cloudflare managed `robots.txt` and Content Signals: https://developers.cloudflare.com/bots/additional-configurations/managed-robots-txt/
- IsAgentReady methodology: https://isagentready.com/en/about
- RFC 9309 Robots Exclusion Protocol: https://www.rfc-editor.org/rfc/rfc9309
- RFC 8288 Web Linking: https://www.rfc-editor.org/rfc/rfc8288
- RFC 8414 OAuth 2.0 Authorization Server Metadata: https://www.rfc-editor.org/rfc/rfc8414
- RFC 9727 API Catalog: https://www.rfc-editor.org/rfc/rfc9727.html
- RFC 9728 OAuth 2.0 Protected Resource Metadata: https://www.ietf.org/rfc/rfc9728.html
- A2A specification repository: https://github.com/a2aproject/A2A/blob/main/docs/specification.md
