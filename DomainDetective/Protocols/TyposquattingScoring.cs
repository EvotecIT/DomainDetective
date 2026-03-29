using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Tunables for typosquatting candidate risk scoring.
/// </summary>
public sealed class TyposquattingScoringOptions
{
    public int ActiveScore { get; set; } = 35;
    public int RegisteredScore { get; set; } = 18;
    public int DelegatedScore { get; set; } = 5;
    public int DistanceOneScore { get; set; } = 12;
    public int DistanceTwoScore { get; set; } = 6;
    public int HomoglyphScore { get; set; } = 14;
    public int CommonMutationScore { get; set; } = 8;
    public int BrandLikeScore { get; set; } = 10;
    public int HttpReachableScore { get; set; } = 10;
    public int HttpHealthyScore { get; set; } = 5;
    public int ThreatListedScore { get; set; } = 25;
    public int ThreatSeverityBoost { get; set; } = 10;
    public int WebTechnologyScore { get; set; } = 4;
    public int EnrichedIpScore { get; set; } = 3;
    public int RegistrarKnownScore { get; set; } = 2;
    public int ResponsiveMailInfrastructureScore { get; set; } = 12;
    public int MailInterceptionScore { get; set; } = 18;
    public int LikelyOwnedPenalty { get; set; } = 35;
    public int LikelyExternalBoost { get; set; } = 18;
    public int MultiCandidateClusterBoost { get; set; } = 8;
    public int StrongContentSimilarityBoost { get; set; } = 22;
    public int ModerateContentSimilarityBoost { get; set; } = 10;
    public int StrongScreenshotVisualSimilarityBoost { get; set; } = 22;
    public int StrongSocialVisualSimilarityBoost { get; set; } = 18;
    public int StrongIconVisualSimilarityBoost { get; set; } = 12;
    public int ModerateScreenshotVisualSimilarityBoost { get; set; } = 10;
    public int ModerateSocialVisualSimilarityBoost { get; set; } = 8;
    public int ModerateIconVisualSimilarityBoost { get; set; } = 5;
    public int MediumThreshold { get; set; } = 30;
    public int HighThreshold { get; set; } = 55;
    public int CriticalThreshold { get; set; } = 75;
}

/// <summary>
/// Reusable scorer for ranking typosquatting candidates.
/// </summary>
public static class TyposquattingCandidateScorer
{
    public static void ScoreCandidates(IReadOnlyList<TyposquattingCandidate>? candidates, TyposquattingScoringOptions? options = null)
    {
        if (candidates == null || candidates.Count == 0)
        {
            return;
        }

        options ??= new TyposquattingScoringOptions();
        foreach (var candidate in candidates)
        {
            ScoreCandidate(candidate, options);
        }
    }

    public static void ScoreCandidate(TyposquattingCandidate candidate, TyposquattingScoringOptions? options = null)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        options ??= new TyposquattingScoringOptions();
        var reasons = new List<string>();
        var score = 0;

        if (candidate.Resolves)
        {
            score += options.ActiveScore;
            reasons.Add("resolves in DNS");
        }
        else if (candidate.AppearsRegistered)
        {
            score += options.RegisteredScore;
            reasons.Add("shows a DNS footprint");
        }

        if (!candidate.Resolves && (candidate.NsRecords.Count > 0 || candidate.MxRecords.Count > 0))
        {
            score += options.DelegatedScore;
            reasons.Add("has NS/MX delegation");
        }

        if (candidate.EditDistance <= 1)
        {
            score += options.DistanceOneScore;
            reasons.Add("very close string distance");
        }
        else if (candidate.EditDistance == 2)
        {
            score += options.DistanceTwoScore;
            reasons.Add("close string distance");
        }

        if (candidate.Kind == TyposquattingVariantKind.Homoglyph || candidate.Kind == TyposquattingVariantKind.Cyrillic)
        {
            score += options.HomoglyphScore;
            reasons.Add("visual impersonation variant");
        }
        else if (candidate.Kind == TyposquattingVariantKind.BrandCombination
            || candidate.Kind == TyposquattingVariantKind.Dictionary
            || candidate.Kind == TyposquattingVariantKind.TldSwap)
        {
            score += options.BrandLikeScore;
            reasons.Add("brand-like naming pattern");
        }
        else
        {
            score += options.CommonMutationScore;
            reasons.Add("common typo mutation");
        }

        var enrichment = candidate.Enrichment;
        if (enrichment?.Http?.IsReachable == true)
        {
            score += options.HttpReachableScore;
            reasons.Add("reachable over HTTPS");
            if (enrichment.Http.StatusCode is >= 200 and < 400)
            {
                score += options.HttpHealthyScore;
                reasons.Add("returns a healthy HTTP response");
            }
        }

        if (enrichment?.ThreatIntel?.Listings?.Any(listing => listing.IsListed) == true)
        {
            score += options.ThreatListedScore;
            reasons.Add("listed by threat intelligence");
            if (!string.IsNullOrWhiteSpace(enrichment.ThreatIntel.Severity)
                && (enrichment.ThreatIntel.Severity.Contains("high", StringComparison.OrdinalIgnoreCase)
                    || enrichment.ThreatIntel.Severity.Contains("critical", StringComparison.OrdinalIgnoreCase)))
            {
                score += options.ThreatSeverityBoost;
                reasons.Add("high-severity reputation signal");
            }
        }

        if ((enrichment?.WebStaticScan?.TechDetections?.Count ?? 0) > 0)
        {
            score += options.WebTechnologyScore;
            reasons.Add("hosts a non-trivial website");
        }

        if ((enrichment?.IpEnrichment?.UniqueIpCount ?? 0) > 0)
        {
            score += options.EnrichedIpScore;
            reasons.Add("has routable IP infrastructure");
        }

        if (!string.IsNullOrWhiteSpace(enrichment?.Whois?.Registrar))
        {
            score += options.RegistrarKnownScore;
            reasons.Add("registrar information available");
        }

        if (enrichment?.SmtpBanner?.ServerResults?.Any(static result => result.Value?.StartsWith220 == true) == true)
        {
            score += options.ResponsiveMailInfrastructureScore;
            reasons.Add("mail exchanger responds over SMTP");
        }

        if (enrichment?.SmtpRecipientAcceptance?.ServerResults?.Any(static result => result.Value?.Accepted == true) == true)
        {
            score += options.MailInterceptionScore;
            reasons.Add("mail exchanger accepts recipients at the lookalike domain");
        }

        if (candidate.Ownership?.LikelyOwned == true)
        {
            score -= options.LikelyOwnedPenalty;
            reasons.Add("ownership signals overlap with the source domain");
        }
        else if (candidate.Ownership?.LikelyExternal == true)
        {
            score += options.LikelyExternalBoost;
            reasons.Add("infrastructure is distinct from the source domain");
        }

        if (candidate.InfrastructureCluster?.HasMultipleCandidates == true)
        {
            score += options.MultiCandidateClusterBoost;
            reasons.Add("shares external infrastructure with other lookalike domains");
        }

        if (candidate.ContentSimilarity?.LikelyImpersonating == true)
        {
            score += options.StrongContentSimilarityBoost;
            reasons.Add("content resembles the source website");
        }
        else if ((candidate.ContentSimilarity?.Score ?? 0) >= 15)
        {
            score += options.ModerateContentSimilarityBoost;
            reasons.Add("content partially resembles the source website");
        }

        if (candidate.VisualSimilarity?.LikelyClone == true)
        {
            score += GetStrongVisualBoost(candidate.VisualSimilarity.MatchedArtifactKind, options);
            reasons.Add("visual appearance resembles the source " + GetVisualArtifactLabel(candidate.VisualSimilarity.MatchedArtifactKind));
        }
        else if ((candidate.VisualSimilarity?.Score ?? 0) >= 60)
        {
            score += GetModerateVisualBoost(candidate.VisualSimilarity!.MatchedArtifactKind, options);
            reasons.Add("visual fingerprint partially resembles the source " + GetVisualArtifactLabel(candidate.VisualSimilarity.MatchedArtifactKind));
        }

        score = Math.Max(0, Math.Min(100, score));
        candidate.RiskScore = score;
        candidate.RiskLevel = score >= options.CriticalThreshold
            ? TyposquattingRiskLevel.Critical
            : score >= options.HighThreshold
                ? TyposquattingRiskLevel.High
                : score >= options.MediumThreshold
                    ? TyposquattingRiskLevel.Medium
                    : score > 0
                        ? TyposquattingRiskLevel.Low
                        : TyposquattingRiskLevel.None;
        candidate.RiskReasons = reasons
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        candidate.RiskSummary = reasons.Count > 0
            ? string.Join(", ", candidate.RiskReasons.Take(3))
            : "no notable signals";
    }

    private static int GetStrongVisualBoost(TyposquattingVisualArtifactKind kind, TyposquattingScoringOptions options)
    {
        return kind switch
        {
            TyposquattingVisualArtifactKind.Screenshot => options.StrongScreenshotVisualSimilarityBoost,
            TyposquattingVisualArtifactKind.OpenGraphImage or TyposquattingVisualArtifactKind.TwitterImage => options.StrongSocialVisualSimilarityBoost,
            TyposquattingVisualArtifactKind.Favicon or TyposquattingVisualArtifactKind.AppleTouchIcon => options.StrongIconVisualSimilarityBoost,
            _ => options.StrongIconVisualSimilarityBoost
        };
    }

    private static int GetModerateVisualBoost(TyposquattingVisualArtifactKind kind, TyposquattingScoringOptions options)
    {
        return kind switch
        {
            TyposquattingVisualArtifactKind.Screenshot => options.ModerateScreenshotVisualSimilarityBoost,
            TyposquattingVisualArtifactKind.OpenGraphImage or TyposquattingVisualArtifactKind.TwitterImage => options.ModerateSocialVisualSimilarityBoost,
            TyposquattingVisualArtifactKind.Favicon or TyposquattingVisualArtifactKind.AppleTouchIcon => options.ModerateIconVisualSimilarityBoost,
            _ => options.ModerateIconVisualSimilarityBoost
        };
    }

    private static string GetVisualArtifactLabel(TyposquattingVisualArtifactKind kind)
    {
        return kind switch
        {
            TyposquattingVisualArtifactKind.Screenshot => "rendered page",
            TyposquattingVisualArtifactKind.OpenGraphImage => "social preview image",
            TyposquattingVisualArtifactKind.TwitterImage => "social preview image",
            TyposquattingVisualArtifactKind.AppleTouchIcon => "touch icon",
            TyposquattingVisualArtifactKind.Favicon => "favicon",
            _ => "visual asset"
        };
    }
}
