using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Tunables for combined analyst-facing typosquatting disposition.
/// </summary>
public sealed class TyposquattingDispositionOptions
{
    public int LikelyMaliciousRiskThreshold { get; set; } = 70;
    public int LikelyImpersonationRiskThreshold { get; set; } = 50;
}

/// <summary>
/// Computes analyst-friendly candidate disposition from combined risk, ownership, and impersonation signals.
/// </summary>
public static class TyposquattingDispositionAnalyzer
{
    public static void Apply(IReadOnlyList<TyposquattingCandidate>? candidates, TyposquattingDispositionOptions? options = null)
    {
        if (candidates == null || candidates.Count == 0)
        {
            return;
        }

        options ??= new TyposquattingDispositionOptions();
        foreach (var candidate in candidates)
        {
            Apply(candidate, options);
        }
    }

    public static void Apply(TyposquattingCandidate candidate, TyposquattingDispositionOptions? options = null)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        options ??= new TyposquattingDispositionOptions();
        var reasons = new List<string>();

        if (!candidate.AppearsRegistered)
        {
            reasons.Add("candidate appears unregistered and available for defensive registration");
            SetDisposition(candidate, TyposquattingDisposition.Available, reasons);
            return;
        }

        if (candidate.Ownership?.LikelyOwned == true)
        {
            reasons.Add("ownership signals overlap with the protected source estate");
            SetDisposition(candidate, TyposquattingDisposition.DefensiveOwned, reasons);
            return;
        }

        var contentClone = candidate.ContentSimilarity?.LikelyImpersonating == true;
        var visualClone = candidate.VisualSimilarity?.LikelyClone == true;
        var external = candidate.Ownership?.LikelyExternal == true;
        var threatListed = candidate.Enrichment?.ThreatIntel?.Listings?.Any(listing => listing.IsListed) == true;
        var reachable = candidate.Enrichment?.Http?.IsReachable == true || candidate.Resolves;
        var healthyHttp = candidate.Enrichment?.Http?.StatusCode is >= 200 and < 400;
        var highRisk = candidate.RiskScore >= options.LikelyMaliciousRiskThreshold;
        var mediumRisk = candidate.RiskScore >= options.LikelyImpersonationRiskThreshold;
        var impersonationSignals = contentClone || visualClone;

        if (contentClone)
        {
            reasons.Add("web content resembles the source site");
        }

        if (visualClone)
        {
            reasons.Add("visual assets resemble the source site");
        }

        if (external)
        {
            reasons.Add("infrastructure appears external to the source estate");
        }

        if (threatListed)
        {
            reasons.Add("candidate is listed by threat intelligence");
        }

        if (healthyHttp)
        {
            reasons.Add("candidate serves a live web response");
        }
        else if (reachable)
        {
            reasons.Add("candidate resolves or is reachable");
        }

        if (impersonationSignals && external && (threatListed || (healthyHttp && highRisk)))
        {
            SetDisposition(candidate, TyposquattingDisposition.LikelyMalicious, reasons);
            return;
        }

        if (impersonationSignals && (external || reachable || mediumRisk))
        {
            SetDisposition(candidate, TyposquattingDisposition.LikelyImpersonation, reasons);
            return;
        }

        if (reasons.Count == 0)
        {
            reasons.Add("candidate is registered or delegated and should be monitored");
        }

        SetDisposition(candidate, TyposquattingDisposition.Monitor, reasons);
    }

    private static void SetDisposition(
        TyposquattingCandidate candidate,
        TyposquattingDisposition disposition,
        IReadOnlyList<string> reasons)
    {
        candidate.Disposition = disposition;
        candidate.DispositionReasons = reasons
            .Where(static reason => !string.IsNullOrWhiteSpace(reason))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        candidate.DispositionSummary = candidate.DispositionReasons.Count > 0
            ? candidate.DispositionReasons[0]
            : disposition.ToString();
    }
}
