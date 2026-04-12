using System.Collections.Generic;
using DomainDetective.Definitions;

namespace DomainDetective;

/// <summary>Classification result for a single domain.</summary>
public sealed class MailDomainClassificationResult {
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; init; } = string.Empty;
    /// <summary>Gets or sets the classification value.</summary>
    public MailDomainClassificationCategory Classification { get; init; }
    /// <summary>Gets or sets the confidence value.</summary>
    public MailDomainClassificationConfidence Confidence { get; init; }
    /// <summary>Gets or sets the signals value.</summary>
    public MailDomainSignalSummary Signals { get; init; } = new();
    /// <summary>Gets or sets the classification reason value.</summary>
    public string ClassificationReason { get; init; } = string.Empty;
    /// <summary>Gets or sets the receiving signals value.</summary>
    public IReadOnlyList<string> ReceivingSignals { get; init; } = new List<string>();
    /// <summary>Gets or sets the sending signals value.</summary>
    public IReadOnlyList<string> SendingSignals { get; init; } = new List<string>();
    /// <summary>Gets or sets the spf includes resolved value.</summary>
    public IReadOnlyList<string> SPFIncludesResolved { get; init; } = new List<string>();
    /// <summary>Gets or sets the dkim selectors found value.</summary>
    public IReadOnlyList<string> DKIMSelectorsFound { get; init; } = new List<string>();
    /// <summary>Gets or sets the score value.</summary>
    public double Score { get; init; }
    /// <summary>Gets or sets the score breakdown value.</summary>
    public IReadOnlyDictionary<string, double> ScoreBreakdown { get; init; } = new Dictionary<string, double>();
    /// <summary>Gets or sets the rfc references value.</summary>
    public IReadOnlyList<StandardReference> RfcReferences { get; init; } = new List<StandardReference>();

    // Provider chain (best-effort inference)
    /// <summary>Gets or sets the provider primary value.</summary>
    public string? ProviderPrimary { get; init; }
    /// <summary>Gets or sets the provider gateways value.</summary>
    public IReadOnlyList<string> ProviderGateways { get; init; } = new List<string>();
    /// <summary>Gets or sets the provider outbound value.</summary>
    public IReadOnlyList<string> ProviderOutbound { get; init; } = new List<string>();

    // BIMI eligibility hints (best-effort; actual display depends on receivers)
    /// <summary>Gets or sets the bimi eligible value.</summary>
    public bool? BimiEligible { get; init; }
    /// <summary>Gets or sets the bimi eligibility reason value.</summary>
    public string? BimiEligibilityReason { get; init; }
    /// <summary>Gets or sets the bimi notes value.</summary>
    public IReadOnlyList<string> BimiNotes { get; init; } = new List<string>();

    // Aggregated assessments from contributing analyses (SPF, DKIM, MX, MTA-STS, TLS-RPT, DANE, BIMI, APEX)
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; init; } = new List<Assessment>();

    // Identity provider hints (OIDC discovery / GetUserRealm)
    /// <summary>Gets or sets the idp tenant id value.</summary>
    public string? IdpTenantId { get; init; }
    /// <summary>Gets or sets the idp name space type value.</summary>
    public string? IdpNameSpaceType { get; init; }
    /// <summary>Gets or sets the idp federated auth url value.</summary>
    public string? IdpFederatedAuthUrl { get; init; }
}
