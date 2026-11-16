using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Profiles;

namespace DomainDetective.Reports;

/// <summary>Shared wording for the risk profile, used by every renderer.</summary>
public static partial class AssessmentReportWording {
    /// <summary>How many gaps a summary lists.</summary>
    public const int RiskGapCount = 3;

    /// <summary>Panel title: "How risky is example.com?".</summary>
    public static string RiskTitle(string domain) => "How risky is " + domain + "?";

    /// <summary>One line under the title.</summary>
    public const string RiskSubtitle = "What was observed about this domain, and how much of it could be seen. Configuration is graded separately.";

    /// <summary>"High · 68", "None · 0" or "Not rated".</summary>
    public static string RiskValue(DomainRiskProfile profile) =>
        !profile.Rated || profile.RiskLevel == DomainRiskLevel.None ? RiskWord(profile)
            : RiskWord(profile) + " · " + profile.RiskScore.ToString(CultureInfo.InvariantCulture);

    /// <summary>Level name.</summary>
    public static string RiskLevelLabel(DomainRiskLevel level) => level switch {
        DomainRiskLevel.Critical => "Critical",
        DomainRiskLevel.High => "High",
        DomainRiskLevel.Medium => "Medium",
        DomainRiskLevel.Low => "Low",
        _ => "None"
    };

    /// <summary>"Medium · 0.74".</summary>
    public static string ConfidenceValue(DomainRiskProfile profile) =>
        ((int)Math.Round(profile.EvidenceScore * 100, MidpointRounding.AwayFromZero)).ToString(CultureInfo.InvariantCulture) + "% seen · " +
        ConfidenceLabel(profile.Confidence).ToLowerInvariant() + " confidence";

    /// <summary>Confidence level name.</summary>
    public static string ConfidenceLabel(EvidenceConfidence confidence) => confidence switch {
        EvidenceConfidence.High => "High",
        EvidenceConfidence.Medium => "Medium",
        _ => "Low"
    };

    /// <summary>One sentence: the verdict, never turning missing evidence into safety.</summary>
    public static string RiskVerdict(DomainRiskProfile profile) {
        if (!profile.Rated) return "Not rated: too little evidence was collected to rate this domain.";
        if (profile.RiskLevel == DomainRiskLevel.None && profile.Watch.Count > 0) {
            return "No risk signals about the domain itself; watch: " + string.Join("; ", profile.Watch) + ".";
        }
        string confidence = ConfidenceLabel(profile.Confidence).ToLowerInvariant() + " confidence (" + profile.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) + ")";
        if (profile.RiskLevel == DomainRiskLevel.None) {
            return profile.Confidence == EvidenceConfidence.High
                ? "No risk signals found, with " + confidence + "."
                : "No risk signals found in the evidence collected, with " + confidence + ".";
        }
        return RiskLevelLabel(profile.RiskLevel) + " risk (" + profile.RiskScore.ToString(CultureInfo.InvariantCulture) + ") with " +
               ConfidenceLabel(profile.Confidence).ToLowerInvariant() + " confidence (" + profile.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) + ").";
    }

    /// <summary>Why confidence is where it is, or null.</summary>
    public static string? ConfidenceNote(DomainRiskProfile profile) {
        if (profile.RestsOn != null) {
            return "The " + RiskLevelLabel(profile.RiskLevel) + " level rests on " + profile.RestsOn + " alone, so confidence is capped at Medium until a second source agrees.";
        }
        if (profile.Corroborated) return "More than one independent source supports the level.";
        if (profile.ConfidenceScore < 0.5) return "Several sources did not answer or were not queried.";
        return null;
    }

    /// <summary>Signed points: "+40", "-5", "0".</summary>
    public static string Points(int points) => points > 0 ? "+" + points.ToString(CultureInfo.InvariantCulture) : points.ToString(CultureInfo.InvariantCulture);

    /// <summary>Facet name.</summary>
    public static string FacetLabel(ProfileFacetKind kind) => kind switch {
        ProfileFacetKind.Reputation => "Reputation",
        ProfileFacetKind.Registration => "Registration",
        ProfileFacetKind.Certificates => "Certificates",
        ProfileFacetKind.Dns => "DNS",
        ProfileFacetKind.Network => "Network",
        ProfileFacetKind.Web => "Web technologies",
        _ => "History"
    };

    /// <summary>Evidence state words.</summary>
    public static string EvidenceStateLabel(EvidenceState state) => state switch {
        EvidenceState.Observed => "Seen",
        EvidenceState.Clean => "Answered, nothing found",
        EvidenceState.Partial => "Partial",
        EvidenceState.Failed => "Failed",
        EvidenceState.NotQueried => "Not queried",
        _ => "Not available"
    };

    /// <summary>Facet coverage: "80%", or why it doesn't count: "not run".</summary>
    public static string FacetCoverage(ProfileFacet facet) {
        if (!facet.Counted) return facet.Kind == ProfileFacetKind.History ? "not available" : "not run";
        return ((int)Math.Round(facet.Coverage * 100, MidpointRounding.AwayFromZero)).ToString(CultureInfo.InvariantCulture) + "%";
    }

    /// <summary>What a facet is missing, for example "VirusTotal not queried; OpenPhish not queried", or "complete".</summary>
    public static string FacetEvidence(ProfileFacet facet) {
        if (!facet.Counted) {
            return facet.Kind == ProfileFacetKind.History
                ? "Passive DNS history is not collected by DomainDetective"
                : "Web scan not run";
        }
        List<string> missing = facet.Evidence
            .Where(static i => i.State is not (EvidenceState.Observed or EvidenceState.Clean))
            .Select(static i => i.Label + " " + EvidenceStateLabel(i.State).ToLowerInvariant() + (i.State == EvidenceState.Partial && !string.IsNullOrWhiteSpace(i.Note) ? " (" + i.Note + ")" : string.Empty))
            .ToList();
        return missing.Count == 0 ? "Complete" : string.Join("; ", missing);
    }

    /// <summary>Gap line: "Add a VirusTotal API key: threat feeds answering go from 1 to 2 of 5".</summary>
    public static string GapLine(EvidenceGap gap) => gap.Action;

    /// <summary>The headline word for the risk: "High risk", "Watch", "No signals", "Clear" or "Not rated".</summary>
    public static string RiskWord(DomainRiskProfile profile) {
        if (!profile.Rated) return "Not rated";
        if (profile.RiskLevel != DomainRiskLevel.None) return RiskLevelLabel(profile.RiskLevel) + " risk";
        if (profile.Watch.Count > 0) return "Watch";
        if (profile.Signals.Any(static s => s.Points > 0)) return "Negligible";
        return profile.Confidence == EvidenceConfidence.High ? "Clear" : "No signals";
    }

    /// <summary>One line under the risk word: the strongest signal, the watch item, or what the verdict rests on.</summary>
    public static string RiskReason(DomainRiskProfile profile) {
        if (!profile.Rated) return "Too little evidence was collected to rate this domain.";
        RiskSignal? top = profile.Signals.FirstOrDefault(static s => s.Points > 0);
        if (top != null && profile.RiskLevel != DomainRiskLevel.None) return top.Reason + ".";
        if (top != null) return "A small signal is outweighed by what counts in its favour: " + LowerFirstSignal(top.Reason) + ".";
        if (profile.Watch.Count > 0) return "Nothing against the domain itself; " + profile.Watch[0] + ".";
        return profile.Confidence == EvidenceConfidence.High
            ? "Nothing in registration, reputation, certificates or DNS counts against it."
            : "Nothing found so far, but part of the evidence is missing.";
    }

    private static string LowerFirstSignal(string text) =>
        text.Length > 1 && char.IsUpper(text[0]) && char.IsLower(text[1]) ? char.ToLowerInvariant(text[0]) + text.Substring(1) : text;

    /// <summary>"71% of evidence seen".</summary>
    public static string ConfidencePercent(DomainRiskProfile profile) =>
        ((int)Math.Round(profile.EvidenceScore * 100, MidpointRounding.AwayFromZero)).ToString(CultureInfo.InvariantCulture) + "% of evidence seen";

    /// <summary>How much of an area's evidence was seen, in words.</summary>
    public static string FacetState(ProfileFacet facet) {
        if (!facet.Counted) return facet.Kind == ProfileFacetKind.History ? "not available" : "not scanned";
        return facet.Coverage >= 0.995 ? "seen" : facet.Coverage <= 0.005 ? "not seen" : "partly seen";
    }

    /// <summary>The block a facet's facts are shown in: Ownership, Infrastructure, Certificates or Reputation.</summary>
    public static string FactBlock(ProfileFacetKind kind) => kind switch {
        ProfileFacetKind.Registration => "Ownership",
        ProfileFacetKind.Certificates => "Certificates",
        ProfileFacetKind.Reputation => "Reputation",
        _ => "Infrastructure"
    };

    /// <summary>Fact blocks in display order.</summary>
    public static IReadOnlyList<string> FactBlocks { get; } = new[] { "Ownership", "Infrastructure", "Certificates", "Reputation" };

    /// <summary>Points a risk signal is worth, for display.</summary>
    public static IEnumerable<RiskSignal> TrustSignals(DomainRiskProfile profile) => profile.Signals.Where(static s => s.Points < 0);

    /// <summary>The gaps worth listing in a summary.</summary>
    public static IEnumerable<EvidenceGap> TopGaps(DomainRiskProfile profile, int count = RiskGapCount) =>
        profile.Gaps.Where(static g => g.ConfidenceGain >= 0.01).Take(count);

    /// <summary>Signals worth showing: all that moved the score.</summary>
    public static IEnumerable<RiskSignal> ShownSignals(DomainRiskProfile profile) => profile.Signals.Where(static s => s.Points != 0);

    /// <summary>Signal source line: "Threat intel · sets floor: High".</summary>
    public static string SignalSource(RiskSignal signal) => signal.Decisive ? signal.Source + " · holds the level at High" : signal.Source;

    /// <summary>Domains that have a risk profile, riskiest first: rated before not rated, then score, then confidence.</summary>
    public static IEnumerable<DomainAssessment> RiskOrder(DomainAssessmentReport report) =>
        report.Domains.Where(static d => d.RiskProfile != null)
            .OrderByDescending(static d => d.RiskProfile!.Rated)
            .ThenByDescending(static d => d.RiskProfile!.RiskScore)
            .ThenByDescending(static d => d.RiskProfile!.ConfidenceScore)
            .ThenBy(static d => d.Domain, StringComparer.OrdinalIgnoreCase);

    /// <summary>Short sentence about the score scale for the About section.</summary>
    public const string RiskScaleNote =
        "Risk adds points for observed signals, capped per area, from 0 to 100: Low above 0, Medium from 30, High from 55, Critical from 75. " +
        "A live listing on a phishing or malware feed holds the level at High. Missing evidence lowers confidence, never the score.";
}
