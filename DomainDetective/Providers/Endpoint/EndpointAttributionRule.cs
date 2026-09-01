using System.Collections.Generic;

namespace DomainDetective.Providers.Endpoint;

/// <summary>
/// Declarative, serializable rule used to attribute an endpoint to a provider service.
/// </summary>
public sealed class EndpointAttributionRule {
    /// <summary>Stable provider identifier.</summary>
    public string ProviderId { get; set; } = string.Empty;

    /// <summary>Stable service identifier within the provider.</summary>
    public string ServiceId { get; set; } = string.Empty;

    /// <summary>Human-readable classification.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Stable rule identifier.</summary>
    public string RuleId { get; set; } = string.Empty;

    /// <summary>Rule version used in persisted evidence.</summary>
    public string RuleVersion { get; set; } = string.Empty;

    /// <summary>Source or provenance note for the rule.</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>Logical hostname prefixes. These are intentionally weak signals.</summary>
    public List<string> HostnamePrefixes { get; } = new();

    /// <summary>DNS CNAME suffixes.</summary>
    public List<string> CnameSuffixes { get; } = new();

    /// <summary>Point-in-time address prefixes in CIDR notation.</summary>
    public List<string> IpAddressPrefixes { get; } = new();

    /// <summary>Azure service-tag names whose current prefixes support this rule.</summary>
    public List<string> AzureServiceTagNames { get; } = new();

    /// <summary>Case-insensitive certificate issuer fragments.</summary>
    public List<string> CertificateIssuerContains { get; } = new();

    /// <summary>HTTP redirect target suffixes.</summary>
    public List<string> RedirectTargetSuffixes { get; } = new();

    /// <summary>Reverse-DNS suffixes.</summary>
    public List<string> ReverseDnsSuffixes { get; } = new();

    /// <summary>Autonomous-system identifiers.</summary>
    public List<string> AutonomousSystemNumbers { get; } = new();

    /// <summary>
    /// Endpoint service labels to which this rule applies. An empty list allows every service.
    /// </summary>
    public List<string> ApplicableServices { get; } = new();

    /// <summary>Endpoint ports to which this rule applies. An empty list allows every port.</summary>
    public List<int> ApplicablePorts { get; } = new();

    /// <summary>Minimum score required to become the primary classification.</summary>
    public double MinimumScore { get; set; } = 0.5;

    /// <summary>
    /// Allows hostname or issuer evidence to establish a primary classification without a stronger
    /// namespace, address, redirect, reverse-DNS, or ASN signal. Defaults to false.
    /// </summary>
    public bool AllowWeakSignalsAsPrimary { get; set; }

    /// <summary>
    /// Requires address-prefix evidence to be corroborated by a different signal kind before it
    /// can establish a primary classification. Use this for point-in-time address seeds.
    /// </summary>
    public bool RequireCorroborationForIpAddressPrimary { get; set; }

    /// <summary>
    /// Signal kinds allowed to corroborate point-in-time address evidence. When empty, any
    /// non-address signal can corroborate it; built-in point-in-time rules use an explicit list.
    /// </summary>
    public List<EndpointAttributionSignalKind> IpAddressPrimaryCorroboratingSignals { get; } = new();
}
