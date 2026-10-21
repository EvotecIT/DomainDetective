using System;
using System.Collections.Generic;

namespace DomainDetective.Providers.Endpoint;

/// <summary>An actual matched signal retained with the rule hit.</summary>
public sealed class EndpointRuleSignal {
    /// <summary>Typed matcher that supplied the evidence.</summary>
    public EndpointMatcherType Type { get; init; }
    /// <summary>Value actually observed for this endpoint.</summary>
    public string Observed { get; init; } = string.Empty;
    /// <summary>Configured operand that matched.</summary>
    public string Matched { get; init; } = string.Empty;
}

/// <summary>A rule's traceable result on one immutable source observation.</summary>
public sealed class EndpointRuleHit {
    /// <summary>Pack identity.</summary>
    public string PackId { get; init; } = string.Empty;
    /// <summary>Pack revision.</summary>
    public string PackVersion { get; init; } = string.Empty;
    /// <summary>Rule identity within the pack.</summary>
    public string RuleId { get; init; } = string.Empty;
    /// <summary>Rule revision.</summary>
    public string RuleVersion { get; init; } = string.Empty;
    /// <summary>Human-readable tag.</summary>
    public string Label { get; init; } = string.Empty;
    /// <summary>Identified provider, empty for generic inventory tags.</summary>
    public string ProviderId { get; init; } = string.Empty;
    /// <summary>Identified service, empty for generic inventory tags.</summary>
    public string ServiceId { get; init; } = string.Empty;
    /// <summary>Actual matched signals and configured purpose.</summary>
    public string Reason { get; init; } = string.Empty;
    /// <summary>Configured presentation effect, never an instruction to delete evidence.</summary>
    public EndpointRuleEffect Effect { get; init; }
    /// <summary>Explicit deployment expectation; consumers still retain expiry/validation actions.</summary>
    public bool Expected { get; init; }
    /// <summary>Source observation identity and independent profile/vantage dimensions.</summary>
    public CertificateObservationIdentity Identity { get; init; } = null!;
    /// <summary>Time of the source assertion, not time of report rendering.</summary>
    public DateTimeOffset ObservedAtUtc { get; init; }
    /// <summary>Evidence explaining this hit.</summary>
    public IReadOnlyList<EndpointRuleSignal> Signals { get; init; } = Array.Empty<EndpointRuleSignal>();
}

/// <summary>One rule's counts; overlapping rules must not be summed as a unique excluded total.</summary>
public sealed class EndpointRuleHitCount {
    /// <summary>Pack identifier.</summary>
    public string PackId { get; init; } = string.Empty;
    /// <summary>Rule identifier.</summary>
    public string RuleId { get; init; } = string.Empty;
    /// <summary>Number of distinct source observations matched.</summary>
    public int MatchedObservations { get; init; }
    /// <summary>Number of distinct logical endpoints matched.</summary>
    public int MatchedEndpoints { get; init; }
    /// <summary>Number of distinct hostnames matched.</summary>
    public int MatchedHosts { get; init; }
}

/// <summary>Reconciled counts over one explicitly supplied observation population.</summary>
public sealed class EndpointRuleHitSummary {
    /// <summary>Every enabled rule, including rules with no hits.</summary>
    public IReadOnlyList<EndpointRuleHitCount> Rules { get; init; } = Array.Empty<EndpointRuleHitCount>();
    /// <summary>Unique source observations excluded or quarantined.</summary>
    public int ExcludedObservations { get; init; }
    /// <summary>Unique logical endpoints excluded or quarantined.</summary>
    public int ExcludedEndpoints { get; init; }
    /// <summary>Distinct rules causing exclusions in this population.</summary>
    public int MatchedRuleCount { get; init; }
    /// <summary>Additional exclusion hits beyond the unique observation total.</summary>
    public int OverlappingHits { get; init; }
}
