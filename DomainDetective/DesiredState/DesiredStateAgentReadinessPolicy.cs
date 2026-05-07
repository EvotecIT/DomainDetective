using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state policy for agent readiness discovery.</summary>
public sealed class DesiredStateAgentReadinessPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Minimum acceptable agent readiness score from 0 to 100.</summary>
    [JsonPropertyName("minimumScore")]
    public int? MinimumScore { get; set; }

    /// <summary>When true, requires robots.txt to be present.</summary>
    [JsonPropertyName("requireRobotsTxt")]
    public bool? RequireRobotsTxt { get; set; }

    /// <summary>When true, requires robots.txt to declare at least one sitemap.</summary>
    [JsonPropertyName("requireSitemap")]
    public bool? RequireSitemap { get; set; }

    /// <summary>When true, requires at least one RFC 8288 Link header relation.</summary>
    [JsonPropertyName("requireLinkHeaders")]
    public bool? RequireLinkHeaders { get; set; }

    /// <summary>When true, requires llms.txt to be present.</summary>
    [JsonPropertyName("requireLlmsTxt")]
    public bool? RequireLlmsTxt { get; set; }

    /// <summary>When true, requires direct markdown negotiation or a markdown alternate.</summary>
    [JsonPropertyName("requireMarkdown")]
    public bool? RequireMarkdown { get; set; }

    /// <summary>When true, requires Content-Signal policy to be present.</summary>
    [JsonPropertyName("requireContentSignals")]
    public bool? RequireContentSignals { get; set; }

    /// <summary>When true, requires robots.txt AI bot directives.</summary>
    [JsonPropertyName("requireAiBotRules")]
    public bool? RequireAiBotRules { get; set; }

    /// <summary>When true, requires RFC 9727 API Catalog discovery.</summary>
    [JsonPropertyName("requireApiCatalog")]
    public bool? RequireApiCatalog { get; set; }

    /// <summary>When true, requires Agent Skills discovery.</summary>
    [JsonPropertyName("requireAgentSkills")]
    public bool? RequireAgentSkills { get; set; }

    /// <summary>When true, requires agents.json discovery.</summary>
    [JsonPropertyName("requireAgentsJson")]
    public bool? RequireAgentsJson { get; set; }

    /// <summary>When true, requires OpenAPI discovery.</summary>
    [JsonPropertyName("requireOpenApi")]
    public bool? RequireOpenApi { get; set; }

    /// <summary>When true, requires HTTPS origin probing.</summary>
    [JsonPropertyName("requireHttps")]
    public bool? RequireHttps { get; set; }

    /// <summary>Minimum number of trust headers that must be present.</summary>
    [JsonPropertyName("minTrustHeaders")]
    public int? MinTrustHeaders { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateAgentReadinessPolicy Clone() {
        return new DesiredStateAgentReadinessPolicy {
            Enabled = Enabled,
            MinimumScore = MinimumScore,
            RequireRobotsTxt = RequireRobotsTxt,
            RequireSitemap = RequireSitemap,
            RequireLinkHeaders = RequireLinkHeaders,
            RequireLlmsTxt = RequireLlmsTxt,
            RequireMarkdown = RequireMarkdown,
            RequireContentSignals = RequireContentSignals,
            RequireAiBotRules = RequireAiBotRules,
            RequireApiCatalog = RequireApiCatalog,
            RequireAgentSkills = RequireAgentSkills,
            RequireAgentsJson = RequireAgentsJson,
            RequireOpenApi = RequireOpenApi,
            RequireHttps = RequireHttps,
            MinTrustHeaders = MinTrustHeaders
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateAgentReadinessPolicy? overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.MinimumScore.HasValue) MinimumScore = overlay.MinimumScore;
        if (overlay.RequireRobotsTxt.HasValue) RequireRobotsTxt = overlay.RequireRobotsTxt;
        if (overlay.RequireSitemap.HasValue) RequireSitemap = overlay.RequireSitemap;
        if (overlay.RequireLinkHeaders.HasValue) RequireLinkHeaders = overlay.RequireLinkHeaders;
        if (overlay.RequireLlmsTxt.HasValue) RequireLlmsTxt = overlay.RequireLlmsTxt;
        if (overlay.RequireMarkdown.HasValue) RequireMarkdown = overlay.RequireMarkdown;
        if (overlay.RequireContentSignals.HasValue) RequireContentSignals = overlay.RequireContentSignals;
        if (overlay.RequireAiBotRules.HasValue) RequireAiBotRules = overlay.RequireAiBotRules;
        if (overlay.RequireApiCatalog.HasValue) RequireApiCatalog = overlay.RequireApiCatalog;
        if (overlay.RequireAgentSkills.HasValue) RequireAgentSkills = overlay.RequireAgentSkills;
        if (overlay.RequireAgentsJson.HasValue) RequireAgentsJson = overlay.RequireAgentsJson;
        if (overlay.RequireOpenApi.HasValue) RequireOpenApi = overlay.RequireOpenApi;
        if (overlay.RequireHttps.HasValue) RequireHttps = overlay.RequireHttps;
        if (overlay.MinTrustHeaders.HasValue) MinTrustHeaders = overlay.MinTrustHeaders;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRobotsTxt ??= false;
        RequireSitemap ??= false;
        RequireLinkHeaders ??= false;
        RequireLlmsTxt ??= false;
        RequireMarkdown ??= false;
        RequireContentSignals ??= false;
        RequireAiBotRules ??= false;
        RequireApiCatalog ??= false;
        RequireAgentSkills ??= false;
        RequireAgentsJson ??= false;
        RequireOpenApi ??= false;
        RequireHttps ??= false;
    }
}
