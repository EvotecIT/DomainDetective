using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an agent readiness desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require common agent discovery resources.</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateAgentReadiness -MinimumScore 70 -RequireLlmsTxt $true -RequireMarkdown $true -RequireApiCatalog $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateAgentReadiness")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateAgentReadiness : PSCmdlet {
    /// <para>Enable/disable the agent readiness desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>Minimum acceptable agent readiness score from 0 to 100.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 100)]
    public int? MinimumScore { get; set; }

    /// <para>When true, require robots.txt to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRobotsTxt { get; set; }

    /// <para>When true, require robots.txt to declare at least one sitemap.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireSitemap { get; set; }

    /// <para>When true, require RFC 8288 Link header discovery.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireLinkHeaders { get; set; }

    /// <para>When true, require llms.txt to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireLlmsTxt { get; set; }

    /// <para>When true, require direct markdown negotiation or a markdown alternate.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireMarkdown { get; set; }

    /// <para>When true, require Content-Signal policy.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireContentSignals { get; set; }

    /// <para>When true, require AI bot directives in robots.txt.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAiBotRules { get; set; }

    /// <para>When true, require RFC 9727 API Catalog discovery.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireApiCatalog { get; set; }

    /// <para>When true, require Agent Skills discovery.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAgentSkills { get; set; }

    /// <para>When true, require agents.json discovery.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAgentsJson { get; set; }

    /// <para>When true, require OpenAPI discovery.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireOpenApi { get; set; }

    /// <para>When true, require HTTPS origin probing.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireHttps { get; set; }

    /// <para>Minimum number of trust headers that must be present.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 10)]
    public int? MinTrustHeaders { get; set; }

    /// <summary>Creates an agent readiness policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            AgentReadiness = new DesiredStateAgentReadinessPolicy {
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
            }
        };

        WriteObject(profile);
    }
}
