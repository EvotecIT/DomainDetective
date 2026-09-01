using System;
using System.Collections.Generic;

namespace DomainDetective.Providers.Endpoint;

/// <summary>Confidence assigned to an endpoint attribution candidate.</summary>
public enum EndpointAttributionConfidence {
    /// <summary>No reusable provider or service signal was found.</summary>
    None = 0,
    /// <summary>A weak signal was found and should normally be reviewed.</summary>
    Low = 1,
    /// <summary>A meaningful signal was found but independent corroboration is desirable.</summary>
    Medium = 2,
    /// <summary>A strong namespace, catalog, or multi-signal match was found.</summary>
    High = 3
}

/// <summary>Type of evidence used by endpoint attribution.</summary>
public enum EndpointAttributionSignalKind {
    /// <summary>Logical hostname pattern.</summary>
    Hostname = 0,
    /// <summary>DNS CNAME target suffix.</summary>
    Cname = 1,
    /// <summary>Resolved or connected address prefix.</summary>
    IpAddress = 2,
    /// <summary>Azure service-tag membership.</summary>
    AzureServiceTag = 3,
    /// <summary>TLS certificate issuer text.</summary>
    CertificateIssuer = 4,
    /// <summary>HTTP redirect target suffix.</summary>
    RedirectTarget = 5,
    /// <summary>Reverse-DNS target suffix.</summary>
    ReverseDns = 6,
    /// <summary>Autonomous-system number.</summary>
    AutonomousSystem = 7
}

/// <summary>One explainable signal contributing to a provider or service classification.</summary>
public sealed class EndpointAttributionEvidence {
    /// <summary>Signal type.</summary>
    public EndpointAttributionSignalKind Kind { get; init; }

    /// <summary>Observed value.</summary>
    public string ObservedValue { get; init; } = string.Empty;

    /// <summary>Rule value that matched the observation.</summary>
    public string MatchedValue { get; init; } = string.Empty;

    /// <summary>Score contributed by this signal.</summary>
    public double Score { get; init; }

    /// <summary>Source catalog or observation source.</summary>
    public string Source { get; init; } = string.Empty;
}

/// <summary>One provider or service attribution candidate.</summary>
public sealed class EndpointAttributionCandidate {
    /// <summary>Stable provider identifier.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Stable provider service identifier.</summary>
    public string ServiceId { get; init; } = string.Empty;

    /// <summary>Human-readable classification.</summary>
    public string DisplayName { get; init; } = string.Empty;

    /// <summary>Normalized score between zero and one.</summary>
    public double Score { get; init; }

    /// <summary>Confidence derived from <see cref="Score"/>.</summary>
    public EndpointAttributionConfidence Confidence { get; init; }

    /// <summary>True when the candidate satisfied its rule's primary-classification threshold.</summary>
    public bool EligibleAsPrimary { get; init; }

    /// <summary>Rule identifier.</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>Rule version.</summary>
    public string RuleVersion { get; init; } = string.Empty;

    /// <summary>Signals supporting this candidate.</summary>
    public IReadOnlyList<EndpointAttributionEvidence> Evidence { get; init; } = Array.Empty<EndpointAttributionEvidence>();
}

/// <summary>Explainable endpoint attribution result.</summary>
public sealed class EndpointAttributionResult {
    /// <summary>Highest-scoring candidate that satisfied its primary threshold.</summary>
    public EndpointAttributionCandidate? Primary { get; init; }

    /// <summary>All candidates with at least one signal, including low-confidence review candidates.</summary>
    public IReadOnlyList<EndpointAttributionCandidate> Candidates { get; init; } = Array.Empty<EndpointAttributionCandidate>();

    /// <summary>Catalog version used for built-in rules.</summary>
    public string CatalogVersion { get; init; } = string.Empty;

    /// <summary>Time at which the classification was evaluated.</summary>
    public DateTimeOffset EvaluatedAtUtc { get; init; }

    /// <summary>True when equally ranked eligible candidates prevent an honest primary selection.</summary>
    public bool IsAmbiguous { get; init; }

    /// <summary>Source identifier of the Azure service-tag catalog used during evaluation.</summary>
    public string AzureServiceTagSource { get; init; } = string.Empty;

    /// <summary>Catalog-wide Azure service-tag change number used during evaluation.</summary>
    public string AzureServiceTagChangeNumber { get; init; } = string.Empty;

    /// <summary>Azure cloud reported by the service-tag catalog.</summary>
    public string AzureServiceTagCloud { get; init; } = string.Empty;

    /// <summary>Time at which the Azure service-tag catalog was loaded or retrieved.</summary>
    public DateTimeOffset? AzureServiceTagRetrievedAtUtc { get; init; }
}

/// <summary>Evidence supplied to endpoint attribution.</summary>
public sealed class EndpointAttributionInput {
    /// <summary>Logical endpoint hostname.</summary>
    public string HostName { get; set; } = string.Empty;

    /// <summary>Endpoint port.</summary>
    public int Port { get; set; }

    /// <summary>Endpoint service or protocol label.</summary>
    public string Service { get; set; } = string.Empty;

    /// <summary>DNS CNAME chain, in traversal order.</summary>
    public IReadOnlyList<string> CnameChain { get; set; } = Array.Empty<string>();

    /// <summary>Resolved and connected addresses observed for the endpoint.</summary>
    public IReadOnlyList<string> IpAddresses { get; set; } = Array.Empty<string>();

    /// <summary>TLS certificate issuer text.</summary>
    public string CertificateIssuer { get; set; } = string.Empty;

    /// <summary>Observed HTTP redirect target hosts.</summary>
    public IReadOnlyList<string> RedirectTargets { get; set; } = Array.Empty<string>();

    /// <summary>Observed reverse-DNS hostnames.</summary>
    public IReadOnlyList<string> ReverseDnsNames { get; set; } = Array.Empty<string>();

    /// <summary>Observed autonomous-system numbers, without requiring a particular prefix format.</summary>
    public IReadOnlyList<string> AutonomousSystemNumbers { get; set; } = Array.Empty<string>();

    /// <summary>Optional Azure service-tag catalog used for current range matching.</summary>
    public AzureServiceTagCatalog? AzureServiceTags { get; set; }
}
