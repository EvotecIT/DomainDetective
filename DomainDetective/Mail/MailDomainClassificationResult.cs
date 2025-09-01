using System.Collections.Generic;
using DomainDetective.Definitions;

namespace DomainDetective;

/// <summary>Classification result for a single domain.</summary>
public sealed class MailDomainClassificationResult {
    public string Domain { get; init; }
    public MailDomainClassificationCategory Classification { get; init; }
    public MailDomainClassificationConfidence Confidence { get; init; }
    public MailDomainSignalSummary Signals { get; init; } = new();
    public string ClassificationReason { get; init; }
    public IReadOnlyList<string> ReceivingSignals { get; init; } = new List<string>();
    public IReadOnlyList<string> SendingSignals { get; init; } = new List<string>();
    public IReadOnlyList<string> SPFIncludesResolved { get; init; } = new List<string>();
    public IReadOnlyList<string> DKIMSelectorsFound { get; init; } = new List<string>();
    public double Score { get; init; }
    public IReadOnlyDictionary<string, double> ScoreBreakdown { get; init; } = new Dictionary<string, double>();
    public IReadOnlyList<StandardReference> RfcReferences { get; init; } = new List<StandardReference>();

    // BIMI eligibility hints (best-effort; actual display depends on receivers)
    public bool? BimiEligible { get; init; }
    public string? BimiEligibilityReason { get; init; }
    public IReadOnlyList<string> BimiNotes { get; init; } = new List<string>();

    // Aggregated assessments from contributing analyses (SPF, DKIM, MX, MTA-STS, TLS-RPT, DANE, BIMI, APEX)
    public IReadOnlyList<Assessment> Assessments { get; init; } = new List<Assessment>();
}
