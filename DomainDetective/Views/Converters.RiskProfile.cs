using System;
using System.Globalization;
using DomainDetective.Profiles;

namespace DomainDetective.Views;

public static partial class Converters {
    /// <summary>Builds the risk profile view for a health check that ran at least one of the profile's source checks.</summary>
    /// <param name="health">Health check that ran.</param>
    /// <param name="nowUtc">Evaluation time; defaults to now.</param>
    /// <returns>The view, or null when none of the profile's source checks ran.</returns>
    public static DomainRiskProfileInfo? ConvertRiskProfile(DomainHealthCheck health, DateTimeOffset? nowUtc = null) {
        if (health == null) throw new ArgumentNullException(nameof(health));
        if (!DomainRiskProfileBuilder.HasEvidence(health)) return null;
        DomainRiskProfile profile = DomainRiskProfileBuilder.Build(health, nowUtc);
        return new DomainRiskProfileInfo {
            Subject = health.VerificationDomain ?? profile.Domain,
            Area = AnalysisArea.Reputation,
            Profile = profile,
            Summary = profile.Rated
                ? string.Format(CultureInfo.InvariantCulture, "Risk {0} ({1}); confidence {2} ({3:0.00})", profile.RiskLevel, profile.RiskScore, profile.Confidence, profile.ConfidenceScore)
                : string.Format(CultureInfo.InvariantCulture, "Not rated; confidence {0:0.00}", profile.ConfidenceScore)
        };
    }
}

/// <summary>The domain's risk profile, carried to the assessment report and its exports.</summary>
public sealed class DomainRiskProfileInfo {
    /// <summary>Domain.</summary>
    public string? Subject { get; set; }
    /// <summary>Area.</summary>
    public AnalysisArea Area { get; set; } = AnalysisArea.Security;
    /// <summary>One-line summary.</summary>
    public string? Summary { get; set; }
    /// <summary>The profile.</summary>
    public DomainRiskProfile Profile { get; set; } = new();
}
