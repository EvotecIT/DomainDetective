using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a robots.txt desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require robots.txt and AI bot rules</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateRobots -RequireRecord $true -RequireAiBotRules $true -RequireSitemap $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateRobots")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateRobots : PSCmdlet {
    /// <para>Enable/disable the robots.txt desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require robots.txt to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, disallows fallback to HTTP retrieval when HTTPS fails.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowFallback { get; set; }

    /// <para>When true, require robots.txt to include AI bot directives.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAiBotRules { get; set; }

    /// <para>When true, require robots.txt to declare at least one sitemap.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireSitemap { get; set; }

    /// <summary>Creates a robots.txt policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Robots = new DesiredStateRobotsPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                DisallowFallback = DisallowFallback,
                RequireAiBotRules = RequireAiBotRules,
                RequireSitemap = RequireSitemap
            }
        };

        WriteObject(profile);
    }
}

