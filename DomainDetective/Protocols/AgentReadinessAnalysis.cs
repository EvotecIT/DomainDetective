using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Assesses whether a website exposes machine-readable resources useful to AI crawlers and agents.
/// </summary>
public sealed class AgentReadinessAnalysis : IHasAssessments {
    private const string CategoryDiscoverability = "Discoverability";
    private const string CategoryContent = "Content accessibility";
    private const string CategoryBotPolicy = "Bot access policy";
    private const string CategoryProtocol = "Protocol discovery";
    private const string CategoryTrust = "Security and trust";

    private static readonly string[] _securityHeaderNames = new[] {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy"
    };
    private static readonly HashSet<string> _knownAiBotNames = new(StringComparer.OrdinalIgnoreCase) {
        "gptbot",
        "chatgpt",
        "oai-searchbot",
        "claudebot",
        "anthropic",
        "google-extended",
        "perplexitybot",
        "ccbot",
        "bytespider",
        "facebookbot"
    };
    private static readonly Regex _htmlTitleRegex = new("<title>\\s*[^<]+\\s*</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex _htmlDescriptionRegex = new("<meta\\s+[^>]*(name|property)=[\"'](?:description|og:description)[\"'][^>]*content=[\"'][^\"']+", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex _htmlLanguageRegex = new("<html\\s+[^>]*lang=[\"'][^\"']+", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex _htmlHeadingRegex = new("<h1\\b[^>]*>.*?</h1>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>Subject that was analyzed.</summary>
    public string Subject { get; private set; } = string.Empty;
    /// <summary>Origin URL selected for the scan.</summary>
    public Uri? OriginUri { get; private set; }
    /// <summary>Final main page URL after redirects.</summary>
    public string? MainPageUrl { get; private set; }
    /// <summary>Main page status code.</summary>
    public int? MainPageStatusCode { get; private set; }
    /// <summary>Main page content type.</summary>
    public string? MainPageContentType { get; private set; }
    /// <summary>True when the selected origin used HTTPS.</summary>
    public bool HttpsUsed => OriginUri?.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) == true;
    /// <summary>True when robots.txt was found.</summary>
    public bool RobotsPresent { get; private set; }
    /// <summary>Parsed robots.txt when present.</summary>
    public RobotsFile? Robots { get; private set; }
    /// <summary>Raw robots.txt content when present.</summary>
    public string? RobotsContent { get; private set; }
    /// <summary>Content-Signal policies found in robots.txt or HTTP headers.</summary>
    public List<ContentSignalPolicy> ContentSignals { get; } = new();
    /// <summary>Parsed Link header relations from the main page and agent-facing documents.</summary>
    public List<AgentReadinessLinkRelation> LinkRelations { get; } = new();
    /// <summary>Well-known and linked endpoint probes.</summary>
    public List<AgentReadinessEndpointProbe> EndpointProbes { get; } = new();
    /// <summary>Markdown negotiation result.</summary>
    public MarkdownNegotiationResult Markdown { get; } = new();
    /// <summary>Number of security/trust headers found on the main page response.</summary>
    public int TrustHeaderCount { get; private set; }
    /// <summary>Number of trust headers evaluated.</summary>
    public int TrustHeaderTotal { get; private set; } = _securityHeaderNames.Length;
    /// <summary>Individual checks used by the score.</summary>
    public List<AgentReadinessCheck> Checks { get; } = new();
    /// <summary>Category rollups.</summary>
    public List<AgentReadinessCategoryScore> CategoryScores { get; } = new();
    /// <summary>Total readiness score from 0 to 100.</summary>
    public double Score { get; private set; }
    /// <summary>Structured assessments captured during the analysis.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Actionable recommendations derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Executes the agent readiness scan.</summary>
    public async Task AnalyzeAsync(string subject, InternalLogger? logger = null, AgentReadinessOptions? options = null, CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(subject)) {
            throw new ArgumentNullException(nameof(subject));
        }

        options ??= new AgentReadinessOptions();
        Reset(subject);

        using var client = HttpClientPlatformFactory.CreateRedirectClient(userAgent: options.UserAgent);
        client.Timeout = options.Timeout;

        var main = await FetchMainPageAsync(client, subject, options, cancellationToken).ConfigureAwait(false);
        if (main == null) {
            AddCheck("main-page", CategoryTrust, "Main page reachable", AgentReadinessCheckStatus.Fail, 0, 5, "Main page could not be fetched.", AgentReadinessCodes.MainPageFailed);
            FinalizeScores(options.ScoreProfile);
            return;
        }

        OriginUri = GetOrigin(main.FinalUri);
        MainPageUrl = main.FinalUri.AbsoluteUri;
        MainPageStatusCode = main.StatusCode;
        MainPageContentType = main.ContentType;

        if (main.StatusCode < 200 || main.StatusCode >= 300) {
            AddCheck("main-page", CategoryTrust, "Main page reachable", AgentReadinessCheckStatus.Fail, 0, 5, "Main page returned HTTP " + main.StatusCode.ToString(CultureInfo.InvariantCulture) + ".", AgentReadinessCodes.MainPageFailed);
            FinalizeScores(options.ScoreProfile);
            return;
        }

        CaptureLinkHeaders(main);
        CaptureContentSignals(main, "HTTP header");

        await AnalyzeRobotsAsync(client, options, cancellationToken).ConfigureAwait(false);
        await AnalyzeMarkdownAsync(client, main, options, cancellationToken).ConfigureAwait(false);
        await ProbeAgentEndpointsAsync(client, options, cancellationToken).ConfigureAwait(false);

        AddMainPageChecks(main);
        AddDiscoverabilityChecks();
        AddBotPolicyChecks();
        AddProtocolChecks();
        AddTrustChecks(main);
        FinalizeScores(options.ScoreProfile);

        logger?.WriteVerbose("Agent readiness scan completed for {0}: {1:0.##}", Subject, Score);
    }

    private void Reset(string subject) {
        Subject = subject.Trim();
        OriginUri = null;
        MainPageUrl = null;
        MainPageStatusCode = null;
        MainPageContentType = null;
        RobotsPresent = false;
        Robots = null;
        RobotsContent = null;
        ContentSignals.Clear();
        LinkRelations.Clear();
        EndpointProbes.Clear();
        Checks.Clear();
        CategoryScores.Clear();
        Assessments.Clear();
        Score = 0;
        TrustHeaderCount = 0;
        TrustHeaderTotal = _securityHeaderNames.Length;
        Markdown.RequestedUrl = string.Empty;
        Markdown.StatusCode = null;
        Markdown.ContentType = null;
        Markdown.VaryAccept = false;
        Markdown.DirectMarkdown = false;
        Markdown.AlternateMarkdownUrl = null;
    }

    private async Task<AgentHttpProbe?> FetchMainPageAsync(HttpClient client, string subject, AgentReadinessOptions options, CancellationToken cancellationToken) {
        if (Uri.TryCreate(subject, UriKind.Absolute, out var absolute) &&
            (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)) {
            return await FetchAsync(client, absolute, null, options, cancellationToken).ConfigureAwait(false);
        }

        var trimmed = subject.Trim().TrimEnd('/');
        var https = new Uri("https://" + trimmed + "/");
        var first = await FetchAsync(client, https, null, options, cancellationToken).ConfigureAwait(false);
        if (first != null) {
            return first;
        }

        if (!options.AllowHttpFallback) {
            return null;
        }

        var http = new Uri("http://" + trimmed + "/");
        return await FetchAsync(client, http, null, options, cancellationToken).ConfigureAwait(false);
    }

    private async Task AnalyzeRobotsAsync(HttpClient client, AgentReadinessOptions options, CancellationToken cancellationToken) {
        if (OriginUri == null) {
            return;
        }

        var robotsUri = new Uri(OriginUri, "/robots.txt");
        var probe = await FetchAsync(client, robotsUri, null, options, cancellationToken).ConfigureAwait(false);
        if (probe == null || probe.StatusCode < 200 || probe.StatusCode >= 300 || string.IsNullOrWhiteSpace(probe.Body)) {
            RobotsPresent = false;
            return;
        }

        RobotsPresent = true;
        RobotsContent = probe.Body;
        Robots = RobotsTxtParser.Parse(probe.Body);
        foreach (var policy in ParseContentSignals(probe.Body, "robots.txt")) {
            ContentSignals.Add(policy);
        }
    }

    private async Task AnalyzeMarkdownAsync(HttpClient client, AgentHttpProbe main, AgentReadinessOptions options, CancellationToken cancellationToken) {
        var requestUri = main.FinalUri;
        Markdown.RequestedUrl = requestUri.AbsoluteUri;

        var acceptHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            ["Accept"] = "text/markdown, text/html;q=0.8, text/plain;q=0.6"
        };
        var markdownProbe = await FetchAsync(client, requestUri, acceptHeaders, options, cancellationToken).ConfigureAwait(false);
        if (markdownProbe != null) {
            Markdown.StatusCode = markdownProbe.StatusCode;
            Markdown.ContentType = markdownProbe.ContentType;
            Markdown.DirectMarkdown = IsMarkdownContent(markdownProbe.ContentType, markdownProbe.Body);
            Markdown.VaryAccept = HeaderContains(markdownProbe.Headers, "Vary", "Accept");
            CaptureLinkHeaders(markdownProbe);
            CaptureContentSignals(markdownProbe, "HTTP header");
        }

        var alternate = LinkRelations.FirstOrDefault(link =>
            link.Relation.Equals("alternate", StringComparison.OrdinalIgnoreCase) &&
            link.Type != null &&
            link.Type.IndexOf("markdown", StringComparison.OrdinalIgnoreCase) >= 0);
        if (alternate != null) {
            Markdown.AlternateMarkdownUrl = alternate.Target;
            return;
        }

        if (OriginUri != null) {
            var indexMd = new Uri(OriginUri, "/index.md");
            var indexProbe = await FetchAsync(client, indexMd, null, options, cancellationToken).ConfigureAwait(false);
            if (indexProbe != null && indexProbe.StatusCode >= 200 && indexProbe.StatusCode < 300 && IsMarkdownContent(indexProbe.ContentType, indexProbe.Body)) {
                Markdown.AlternateMarkdownUrl = indexProbe.FinalUri.AbsoluteUri;
            }
        }
    }

    private async Task ProbeAgentEndpointsAsync(HttpClient client, AgentReadinessOptions options, CancellationToken cancellationToken) {
        if (OriginUri == null) {
            return;
        }

        var targets = new List<(string kind, Uri uri, string source)> {
            ("api-catalog", new Uri(OriginUri, "/.well-known/api-catalog"), "well-known"),
            ("oauth-authorization-server", new Uri(OriginUri, "/.well-known/oauth-authorization-server"), "well-known"),
            ("oauth-protected-resource", new Uri(OriginUri, "/.well-known/oauth-protected-resource"), "well-known"),
            ("agent-skills", new Uri(OriginUri, "/.well-known/agent-skills/index.json"), "well-known"),
            ("agent-skills", new Uri(OriginUri, "/.well-known/skills/index.json"), "well-known"),
            ("llms.txt", new Uri(OriginUri, "/llms.txt"), "well-known"),
            ("a2a-agent-card", new Uri(OriginUri, "/.well-known/agent-card.json"), "well-known"),
            ("a2a-agent-card", new Uri(OriginUri, "/.well-known/agent.json"), "well-known"),
            ("mcp", new Uri(OriginUri, "/.well-known/mcp-server"), "well-known"),
            ("mcp", new Uri(OriginUri, "/.well-known/mcp.json"), "well-known"),
            ("agents-json", new Uri(OriginUri, "/agents.json"), "well-known"),
            ("openapi", new Uri(OriginUri, "/openapi.json"), "well-known"),
            ("openapi", new Uri(OriginUri, "/.well-known/openapi.json"), "well-known")
        };

        foreach (var link in LinkRelations) {
            if (link.Relation.Equals("api-catalog", StringComparison.OrdinalIgnoreCase)) {
                if (TryCreateAllowedEndpointUri(link.Target, options, out var uri)) {
                    targets.Add(("api-catalog", uri, "link-header"));
                }
            } else if (link.Relation.Equals("describedby", StringComparison.OrdinalIgnoreCase) &&
                       link.Target.IndexOf("agent-skills", StringComparison.OrdinalIgnoreCase) >= 0) {
                if (TryCreateAllowedEndpointUri(link.Target, options, out var uri)) {
                    targets.Add(("agent-skills", uri, "link-header"));
                }
            } else if (link.Relation.Equals("service-doc", StringComparison.OrdinalIgnoreCase) &&
                       link.Target.EndsWith("/llms.txt", StringComparison.OrdinalIgnoreCase)) {
                if (TryCreateAllowedEndpointUri(link.Target, options, out var uri)) {
                    targets.Add(("llms.txt", uri, "link-header"));
                }
            }
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var maxEndpointProbes = Math.Max(1, options.MaxEndpointProbes);
        for (var i = 0; i < targets.Count && EndpointProbes.Count < maxEndpointProbes; i++) {
            var target = targets[i];
            var key = target.kind + "|" + target.uri.AbsoluteUri;
            if (!seen.Add(key)) {
                continue;
            }

            var outcome = await ProbeEndpointAsync(client, target.kind, target.uri, target.source, options, cancellationToken).ConfigureAwait(false);
            EndpointProbes.Add(outcome.Probe);
            foreach (var discovered in outcome.DiscoveredTargets) {
                if (targets.Count >= maxEndpointProbes) {
                    break;
                }

                if (IsAllowedEndpointUri(discovered.uri, options)) {
                    targets.Add(discovered);
                }
            }
        }
    }

    private async Task<AgentEndpointProbeOutcome> ProbeEndpointAsync(HttpClient client, string kind, Uri uri, string source, AgentReadinessOptions options, CancellationToken cancellationToken) {
        var result = new AgentReadinessEndpointProbe {
            Kind = kind,
            Url = uri.AbsoluteUri,
            DiscoverySource = source
        };
        var outcome = new AgentEndpointProbeOutcome {
            Probe = result
        };

        var probe = await FetchAsync(client, uri, null, options, cancellationToken).ConfigureAwait(false);
        if (probe == null) {
            result.Error = "Fetch failed.";
            return outcome;
        }

        result.StatusCode = probe.StatusCode;
        result.ContentType = probe.ContentType;
        result.Present = probe.StatusCode >= 200 && probe.StatusCode < 300;
        if (result.Present && LooksLikeJson(result.ContentType, probe.Body)) {
            ApplyJsonShape(result, probe.Body);
            if (result.Kind.Equals("api-catalog", StringComparison.OrdinalIgnoreCase)) {
                foreach (var target in ExtractApiCatalogTargets(probe.Body, probe.FinalUri)) {
                    outcome.DiscoveredTargets.Add(target);
                }
            }
        }
        return outcome;
    }

    private void AddMainPageChecks(AgentHttpProbe main) {
        var body = main.Body ?? string.Empty;
        var hasTitle = _htmlTitleRegex.IsMatch(body);
        var hasDescription = _htmlDescriptionRegex.IsMatch(body);
        var hasLanguage = _htmlLanguageRegex.IsMatch(body);
        var hasHeading = _htmlHeadingRegex.IsMatch(body);
        var score = new[] { hasTitle, hasDescription, hasLanguage, hasHeading }.Count(v => v) * 2.5;
        AddCheck(
            "raw-html",
            CategoryContent,
            "Raw HTML contains agent-readable semantics",
            score >= 7.5 ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning,
            score,
            10,
            $"title={hasTitle}; description={hasDescription}; lang={hasLanguage}; h1={hasHeading}",
            score >= 7.5 ? AgentReadinessCodes.RawHtmlStrong : AgentReadinessCodes.RawHtmlWeak);
    }

    private void AddDiscoverabilityChecks() {
        AddCheck("robots", CategoryDiscoverability, "robots.txt", RobotsPresent ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning, RobotsPresent ? 5 : 0, 5, RobotsPresent ? "robots.txt found." : "robots.txt missing.", RobotsPresent ? AgentReadinessCodes.RobotsPresent : AgentReadinessCodes.RobotsMissing);

        var sitemapPresent = Robots?.Sitemaps.Count > 0;
        AddCheck("sitemap", CategoryDiscoverability, "Sitemap declared", sitemapPresent ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning, sitemapPresent ? 5 : 0, 5, sitemapPresent ? string.Join(", ", Robots!.Sitemaps.Take(3)) : "No sitemap found in robots.txt.", sitemapPresent ? AgentReadinessCodes.SitemapPresent : AgentReadinessCodes.SitemapMissing);

        var linkPresent = LinkRelations.Count > 0;
        AddCheck("link-header", CategoryDiscoverability, "Agent-facing Link headers", linkPresent ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning, linkPresent ? 5 : 0, 5, linkPresent ? $"{LinkRelations.Count} Link relation(s) found." : "No Link header relations found.", linkPresent ? AgentReadinessCodes.LinkHeaderPresent : AgentReadinessCodes.LinkHeaderMissing);

        var llmsPresent = EndpointPresent("llms.txt") || ProbePresent("/llms.txt");
        AddCheck("llms-txt", CategoryDiscoverability, "llms.txt", llmsPresent ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning, llmsPresent ? 5 : 0, 5, llmsPresent ? "llms.txt found." : "llms.txt missing.", llmsPresent ? AgentReadinessCodes.LlmsTxtPresent : AgentReadinessCodes.LlmsTxtMissing);

        var agentsPresent = EndpointUsable("agents-json");
        AddCheck("agents-json", CategoryDiscoverability, "agents.json", agentsPresent ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Info, agentsPresent ? 5 : 0, 5, agentsPresent ? "agents.json found." : "agents.json missing.", agentsPresent ? AgentReadinessCodes.AgentsJsonPresent : AgentReadinessCodes.AgentsJsonMissing);

        double markdownScore;
        AgentReadinessCheckStatus markdownStatus;
        string markdownEvidence;
        string markdownCode;
        if (Markdown.DirectMarkdown) {
            markdownScore = 10;
            markdownStatus = AgentReadinessCheckStatus.Pass;
            markdownEvidence = "Accept: text/markdown returned markdown.";
            markdownCode = AgentReadinessCodes.MarkdownDirect;
        } else if (!string.IsNullOrWhiteSpace(Markdown.AlternateMarkdownUrl)) {
            markdownScore = 7;
            markdownStatus = AgentReadinessCheckStatus.Pass;
            markdownEvidence = "Markdown alternate found: " + Markdown.AlternateMarkdownUrl;
            markdownCode = AgentReadinessCodes.MarkdownAlternate;
        } else {
            markdownScore = 0;
            markdownStatus = AgentReadinessCheckStatus.Warning;
            markdownEvidence = "No direct markdown response or markdown alternate found.";
            markdownCode = AgentReadinessCodes.MarkdownMissing;
        }
        AddCheck("markdown", CategoryContent, "Markdown representation", markdownStatus, markdownScore, 10, markdownEvidence, markdownCode);
    }

    private void AddBotPolicyChecks() {
        var aiPolicy = HasAiBotPolicy();
        AddCheck("ai-bot-policy", CategoryBotPolicy, "AI bot policy", aiPolicy ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Info, aiPolicy ? 5 : 0, 5, aiPolicy ? "AI bot user-agent rules found in robots.txt." : "No AI bot user-agent rules found.", aiPolicy ? AgentReadinessCodes.AiBotPolicyPresent : AgentReadinessCodes.AiBotPolicyMissing);

        var contentSignals = ContentSignals.Count > 0;
        AddCheck("content-signals", CategoryBotPolicy, "Content Signals", contentSignals ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning, contentSignals ? 10 : 0, 10, contentSignals ? string.Join("; ", ContentSignals.Select(p => p.RawValue).Distinct().Take(3)) : "No Content-Signal policy found.", contentSignals ? AgentReadinessCodes.ContentSignalsPresent : AgentReadinessCodes.ContentSignalsMissing);
    }

    private void AddProtocolChecks() {
        AddProtocolCheck("api-catalog", "API Catalog", 5, AgentReadinessCodes.ApiCatalogPresent, AgentReadinessCodes.ApiCatalogMissing);
        AddProtocolCheck("agent-skills", "Agent Skills", 5, AgentReadinessCodes.AgentSkillsPresent, AgentReadinessCodes.AgentSkillsMissing);
        AddProtocolCheck("openapi", "OpenAPI", 3, AgentReadinessCodes.OpenApiPresent, AgentReadinessCodes.OpenApiMissing);

        var oauth = EndpointPresent("oauth-authorization-server") || EndpointPresent("oauth-protected-resource");
        AddCheck("oauth-metadata", CategoryProtocol, "OAuth metadata", oauth ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Info, oauth ? 2 : 0, 2, oauth ? "OAuth metadata found." : "OAuth metadata not found.", oauth ? AgentReadinessCodes.OAuthMetadataPresent : AgentReadinessCodes.OAuthMetadataMissing);

        AddProtocolCheck("a2a-agent-card", "A2A Agent Card", 2, AgentReadinessCodes.AgentCardsPresent, AgentReadinessCodes.AgentCardsMissing);
        AddProtocolCheck("mcp", "MCP discovery", 3, AgentReadinessCodes.McpPresent, AgentReadinessCodes.McpMissing);
    }

    private void AddTrustChecks(AgentHttpProbe main) {
        AddCheck("https", CategoryTrust, "HTTPS origin", HttpsUsed ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning, HttpsUsed ? 5 : 0, 5, HttpsUsed ? "Origin uses HTTPS." : "Origin used HTTP fallback.", HttpsUsed ? AgentReadinessCodes.HttpsPresent : AgentReadinessCodes.HttpsMissing);

        var present = _securityHeaderNames.Count(name => main.Headers.ContainsKey(name));
        TrustHeaderCount = present;
        TrustHeaderTotal = _securityHeaderNames.Length;
        var score = present * 2;
        if (score > 10) {
            score = 10;
        }
        AddCheck("security-headers", CategoryTrust, "Trust headers", score >= 8 ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Warning, score, 10, $"{present} of {_securityHeaderNames.Length} trust headers found.", score >= 8 ? AgentReadinessCodes.SecurityHeadersStrong : AgentReadinessCodes.SecurityHeadersWeak);
    }

    private void AddProtocolCheck(string kind, string name, double maxScore, string presentCode, string missingCode) {
        var present = EndpointUsable(kind);
        AddCheck(
            kind,
            CategoryProtocol,
            name,
            present ? AgentReadinessCheckStatus.Pass : AgentReadinessCheckStatus.Info,
            present ? maxScore : 0,
            maxScore,
            present ? $"{name} endpoint found." : $"{name} endpoint not found.",
            present ? presentCode : missingCode);
    }

    private void FinalizeScores(AgentReadinessScoreProfile profile) {
        CategoryScores.Clear();
        var weights = GetWeights(profile);
        foreach (var category in weights.Keys) {
            var checks = Checks.Where(check => check.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToArray();
            var score = checks.Sum(check => check.Score);
            var max = checks.Sum(check => check.MaxScore);
            var weighted = max > 0 ? score / max * weights[category] : 0;
            CategoryScores.Add(new AgentReadinessCategoryScore {
                Category = category,
                Score = score,
                MaxScore = max,
                WeightedScore = weighted,
                Weight = weights[category],
                Passed = checks.Count(check => check.Status == AgentReadinessCheckStatus.Pass),
                Warnings = checks.Count(check => check.Status == AgentReadinessCheckStatus.Warning),
                Failed = checks.Count(check => check.Status == AgentReadinessCheckStatus.Fail)
            });
        }

        Score = Math.Round(CategoryScores.Sum(category => category.WeightedScore), 2);
    }

    private Dictionary<string, double> GetWeights(AgentReadinessScoreProfile profile) {
        if (profile == AgentReadinessScoreProfile.SeoAgentReadiness) {
            return new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) {
                [CategoryDiscoverability] = 30,
                [CategoryContent] = 40,
                [CategoryBotPolicy] = 0,
                [CategoryProtocol] = 15,
                [CategoryTrust] = 15
            };
        }

        if (profile == AgentReadinessScoreProfile.CloudflareLike) {
            return new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) {
                [CategoryDiscoverability] = 30,
                [CategoryContent] = 20,
                [CategoryBotPolicy] = 20,
                [CategoryProtocol] = 20,
                [CategoryTrust] = 10
            };
        }

        return new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) {
            [CategoryDiscoverability] = 25,
            [CategoryContent] = 20,
            [CategoryBotPolicy] = 15,
            [CategoryProtocol] = 25,
            [CategoryTrust] = 15
        };
    }

    private void AddCheck(string id, string category, string name, AgentReadinessCheckStatus status, double score, double maxScore, string evidence, string code) {
        Checks.Add(new AgentReadinessCheck {
            Id = id,
            Category = category,
            Name = name,
            Status = status,
            Score = Math.Max(0, Math.Min(score, maxScore)),
            MaxScore = maxScore,
            Evidence = evidence,
            Code = code
        });

        Assessments.Add(new Assessment {
            Severity = status == AgentReadinessCheckStatus.Fail ? AssessmentSeverity.Error : status == AgentReadinessCheckStatus.Warning ? AssessmentSeverity.Warning : AssessmentSeverity.Info,
            Category = "AgentReadiness",
            Target = Subject,
            Code = code,
            Message = $"{name}: {evidence}"
        });
    }

    private bool HasAiBotPolicy() {
        if (Robots == null) {
            return false;
        }

        foreach (var group in Robots.Groups) {
            foreach (var agent in group.UserAgents) {
                if (IsKnownAiBot(agent)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsKnownAiBot(string value) {
        var trimmed = value.Trim();
        return _knownAiBotNames.Contains(trimmed) ||
               _knownAiBotNames.Any(name => trimmed.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
    }

    private bool EndpointPresent(string kind) {
        return EndpointProbes.Any(probe => probe.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase) && probe.Present);
    }

    private bool EndpointUsable(string kind) {
        return EndpointProbes.Any(probe =>
            probe.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase) &&
            probe.Present &&
            (!RequiresShapeValidation(kind) || probe.ShapeValid));
    }

    private static bool RequiresShapeValidation(string kind) {
        return kind.Equals("api-catalog", StringComparison.OrdinalIgnoreCase) ||
               kind.Equals("agent-skills", StringComparison.OrdinalIgnoreCase) ||
               kind.Equals("agents-json", StringComparison.OrdinalIgnoreCase) ||
               kind.Equals("openapi", StringComparison.OrdinalIgnoreCase);
    }

    private bool ProbePresent(string path) {
        if (OriginUri == null) {
            return false;
        }
        var target = new Uri(OriginUri, path).AbsoluteUri;
        return EndpointProbes.Any(probe => probe.Url.Equals(target, StringComparison.OrdinalIgnoreCase) && probe.Present);
    }

    private void CaptureLinkHeaders(AgentHttpProbe probe) {
        if (!probe.Headers.TryGetValue("Link", out var value)) {
            return;
        }

        foreach (var link in AgentReadinessLinkHeaderParser.Parse(value, probe.FinalUri)) {
            if (!LinkRelations.Any(existing =>
                    existing.Relation.Equals(link.Relation, StringComparison.OrdinalIgnoreCase) &&
                    existing.Target.Equals(link.Target, StringComparison.OrdinalIgnoreCase))) {
                LinkRelations.Add(link);
            }
        }
    }

    private void CaptureContentSignals(AgentHttpProbe probe, string source) {
        if (!probe.Headers.TryGetValue("Content-Signal", out var value)) {
            return;
        }

        var policy = ParseContentSignalValue(value, source);
        if (policy != null) {
            ContentSignals.Add(policy);
        }
    }

    private static IReadOnlyList<ContentSignalPolicy> ParseContentSignals(string content, string source) {
        var policies = new List<ContentSignalPolicy>();
        foreach (var rawLine in content.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None)) {
            var line = rawLine.Trim();
            if (!line.StartsWith("Content-Signal:", StringComparison.OrdinalIgnoreCase)) {
                continue;
            }

            var value = line.Substring("Content-Signal:".Length).Trim();
            var policy = ParseContentSignalValue(value, source);
            if (policy != null) {
                policies.Add(policy);
            }
        }

        return policies;
    }

    private static ContentSignalPolicy? ParseContentSignalValue(string value, string source) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        var policy = new ContentSignalPolicy {
            RawValue = value,
            Source = source
        };
        foreach (var part in value.Split(',')) {
            var pieces = part.Split(new[] { '=' }, 2);
            if (pieces.Length != 2) {
                continue;
            }

            var name = pieces[0].Trim();
            var val = pieces[1].Trim();
            if (name.Equals("search", StringComparison.OrdinalIgnoreCase)) {
                policy.Search = val;
            } else if (name.Equals("ai-input", StringComparison.OrdinalIgnoreCase)) {
                policy.AiInput = val;
            } else if (name.Equals("ai-train", StringComparison.OrdinalIgnoreCase)) {
                policy.AiTrain = val;
            }
        }

        return policy;
    }

    private static bool IsMarkdownContent(string? contentType, string? body) {
        if (contentType != null && contentType.IndexOf("markdown", StringComparison.OrdinalIgnoreCase) >= 0) {
            return true;
        }
        if (string.IsNullOrWhiteSpace(body)) {
            return false;
        }

        var content = body!;
        var trimmed = content.TrimStart();
        return trimmed.StartsWith("# ", StringComparison.Ordinal) || trimmed.StartsWith("## ", StringComparison.Ordinal);
    }

    private static bool LooksLikeJson(string? contentType, string? body) {
        if (contentType != null &&
            (contentType.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0 ||
             contentType.IndexOf("linkset", StringComparison.OrdinalIgnoreCase) >= 0)) {
            return true;
        }
        if (string.IsNullOrWhiteSpace(body)) {
            return false;
        }
        var content = body!;
        var trimmed = content.TrimStart();
        return trimmed.StartsWith("{", StringComparison.Ordinal) || trimmed.StartsWith("[", StringComparison.Ordinal);
    }

    private static void ApplyJsonShape(AgentReadinessEndpointProbe result, string? body) {
        if (string.IsNullOrWhiteSpace(body)) {
            return;
        }

        var content = body!;
        try {
            using var doc = JsonDocument.Parse(content);
            result.ValidJson = true;
            var root = doc.RootElement;
            if (result.Kind.Equals("api-catalog", StringComparison.OrdinalIgnoreCase)) {
                result.ShapeValid = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("linkset", out _);
                result.Shape = result.ShapeValid ? "RFC9727 linkset" : null;
            } else if (result.Kind.Equals("agent-skills", StringComparison.OrdinalIgnoreCase)) {
                result.ShapeValid = root.ValueKind == JsonValueKind.Object &&
                                    root.TryGetProperty("skills", out var skills) &&
                                    skills.ValueKind == JsonValueKind.Array;
                result.Shape = result.ShapeValid ? "Agent Skills index" : null;
            } else if (result.Kind.Equals("agents-json", StringComparison.OrdinalIgnoreCase)) {
                result.ShapeValid = root.ValueKind == JsonValueKind.Object &&
                                    (root.TryGetProperty("resources", out _) ||
                                     root.TryGetProperty("capabilities", out _) ||
                                     root.TryGetProperty("name", out _));
                result.Shape = result.ShapeValid ? "agents.json" : null;
            } else if (result.Kind.Equals("openapi", StringComparison.OrdinalIgnoreCase)) {
                result.ShapeValid = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("openapi", out _);
                result.Shape = result.ShapeValid ? "OpenAPI" : null;
            } else {
                result.ShapeValid = true;
            }
        } catch {
            result.ValidJson = false;
        }
    }

    private static IReadOnlyList<(string kind, Uri uri, string source)> ExtractApiCatalogTargets(string? body, Uri sourceUri) {
        var targets = new List<(string kind, Uri uri, string source)>();
        if (string.IsNullOrWhiteSpace(body)) {
            return targets;
        }

        var content = body!;
        try {
            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("linkset", out var linkset) || linkset.ValueKind != JsonValueKind.Array) {
                return targets;
            }

            foreach (var item in linkset.EnumerateArray()) {
                if (item.ValueKind != JsonValueKind.Object) {
                    continue;
                }

                foreach (var property in item.EnumerateObject()) {
                    if (!IsApiCatalogOpenApiRelation(property.Name) || property.Value.ValueKind != JsonValueKind.Array) {
                        continue;
                    }

                    foreach (var entry in property.Value.EnumerateArray()) {
                        if (TryGetApiCatalogHref(entry, property.Name, out var href) &&
                            Uri.TryCreate(sourceUri, href, out var resolved)) {
                            targets.Add(("openapi", resolved, "api-catalog"));
                        }
                    }
                }
            }
        } catch {
            return targets;
        }

        return targets;
    }

    private static bool IsApiCatalogOpenApiRelation(string relation) {
        return relation.Equals("openapi", StringComparison.OrdinalIgnoreCase) ||
               relation.Equals("service-desc", StringComparison.OrdinalIgnoreCase) ||
               relation.Equals("describedby", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetApiCatalogHref(JsonElement entry, string relation, out string href) {
        href = string.Empty;
        if (entry.ValueKind != JsonValueKind.Object || !entry.TryGetProperty("href", out var hrefElement) || hrefElement.ValueKind != JsonValueKind.String) {
            return false;
        }

        href = hrefElement.GetString() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(href)) {
            return false;
        }

        if (relation.Equals("openapi", StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        if (entry.TryGetProperty("type", out var typeElement) &&
            typeElement.ValueKind == JsonValueKind.String &&
            (typeElement.GetString() ?? string.Empty).IndexOf("openapi", StringComparison.OrdinalIgnoreCase) >= 0) {
            return true;
        }

        return href.IndexOf("openapi", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool HeaderContains(Dictionary<string, string> headers, string name, string token) {
        if (!headers.TryGetValue(name, out var value)) {
            return false;
        }
        return value.Split(',').Any(part => part.Trim().Equals(token, StringComparison.OrdinalIgnoreCase));
    }

    private static Uri GetOrigin(Uri uri) {
        return new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
    }

    private bool TryCreateAllowedEndpointUri(string value, AgentReadinessOptions options, out Uri uri) {
        if (Uri.TryCreate(value, UriKind.Absolute, out var candidate) && IsAllowedEndpointUri(candidate, options)) {
            uri = candidate;
            return true;
        }

        uri = null!;
        return false;
    }

    private bool IsAllowedEndpointUri(Uri uri, AgentReadinessOptions options) {
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) {
            return false;
        }

        if (!options.RestrictEndpointProbesToOriginHost || OriginUri == null) {
            return true;
        }

        return uri.Scheme.Equals(OriginUri.Scheme, StringComparison.OrdinalIgnoreCase) &&
               uri.Port == OriginUri.Port &&
               string.Equals(uri.Host.TrimEnd('.'), OriginUri.Host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
    }

    private async Task<AgentHttpProbe?> FetchAsync(HttpClient client, Uri uri, Dictionary<string, string>? headers, AgentReadinessOptions options, CancellationToken cancellationToken) {
        try {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (headers != null) {
                foreach (var kvp in headers) {
                    request.Headers.TryAddWithoutValidation(kvp.Key, kvp.Value);
                }
            }

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
            var body = response.Content != null ? await response.Content.ReadAsStringAsync().ConfigureAwait(false) : string.Empty;
            if (body.Length > options.MaxBodyCharacters) {
                body = body.Substring(0, options.MaxBodyCharacters);
            }
            var finalUri = response.RequestMessage?.RequestUri ?? uri;
            var probe = new AgentHttpProbe {
                RequestedUri = uri,
                FinalUri = finalUri,
                StatusCode = (int)response.StatusCode,
                ContentType = response.Content?.Headers?.ContentType?.MediaType ?? response.Content?.Headers?.ContentType?.ToString(),
                Body = body
            };
            foreach (var header in response.Headers) {
                probe.Headers[header.Key] = string.Join(",", header.Value);
            }
            if (response.Content?.Headers != null) {
                foreach (var header in response.Content.Headers) {
                    probe.Headers[header.Key] = string.Join(",", header.Value);
                }
            }
            return probe;
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
            throw;
        } catch {
            return null;
        }
    }

    private sealed class AgentHttpProbe {
        public Uri RequestedUri { get; set; } = null!;
        public Uri FinalUri { get; set; } = null!;
        public int StatusCode { get; set; }
        public string? ContentType { get; set; }
        public string Body { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class AgentEndpointProbeOutcome {
        public AgentReadinessEndpointProbe Probe { get; set; } = null!;
        public List<(string kind, Uri uri, string source)> DiscoveredTargets { get; } = new();
    }
}
