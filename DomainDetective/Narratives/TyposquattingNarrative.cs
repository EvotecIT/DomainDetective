using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides typosquatting narrative functionality.</summary>
public static class TyposquattingNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(TyposquattingAnalysis analysis)
    {
        var subjCandidate = analysis.Subject;
        string subj;
        if (subjCandidate != null && !string.IsNullOrWhiteSpace(subjCandidate))
        {
            subj = subjCandidate;
        }
        else
        {
            subj = "(domain)";
        }
        var title = $"Typosquatting Report — {subj}";
        var subtitle = "Typosquatting Assessment";
        var category = "Brand Protection";
        var keywords = $"typosquatting, brand, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Typosquatting involves registering look-alike domains to deceive users or capture traffic.";
        var why = "Monitoring and defensively registering variants reduces impersonation risk.";

        var hi = new List<string>();
        var det = new List<string>();
        var active = analysis.ActiveDomains ?? new List<string>();
        var registered = analysis.RegisteredDomains ?? new List<string>();
        var likelyOwned = analysis.Candidates
            .Where(candidate => candidate.Ownership?.LikelyOwned == true)
            .Select(candidate => candidate.Domain)
            .ToList();
        var likelyExternal = analysis.Candidates
            .Where(candidate => candidate.Ownership?.LikelyExternal == true)
            .OrderByDescending(candidate => candidate.RiskScore)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Domain)
            .ToList();
        var likelyImpersonating = analysis.Candidates
            .Where(candidate => candidate.ContentSimilarity?.LikelyImpersonating == true)
            .OrderByDescending(candidate => candidate.ContentSimilarity?.Score ?? 0)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Domain)
            .ToList();
        var likelyVisualClones = analysis.Candidates
            .Where(candidate => candidate.VisualSimilarity?.LikelyClone == true)
            .OrderByDescending(candidate => candidate.VisualSimilarity?.Score ?? 0)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Domain + " (" + DescribeVisualMatch(candidate.VisualSimilarity) + ")")
            .ToList();
        var mailEnabled = analysis.Candidates
            .Where(candidate => candidate.Enrichment?.SmtpBanner?.ServerResults?.Any(result => result.Value?.StartsWith220 == true) == true)
            .OrderByDescending(candidate => candidate.RiskScore)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Domain)
            .ToList();
        var mailAccepting = analysis.Candidates
            .Where(candidate => candidate.Enrichment?.SmtpRecipientAcceptance?.ServerResults?.Any(result => result.Value?.Accepted == true) == true)
            .OrderByDescending(candidate => candidate.RiskScore)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Domain)
            .ToList();
        var likelyMalicious = analysis.Candidates
            .Where(candidate => candidate.Disposition == TyposquattingDisposition.LikelyMalicious)
            .OrderByDescending(candidate => candidate.RiskScore)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Domain)
            .ToList();
        var likelyImpersonation = analysis.Candidates
            .Where(candidate => candidate.Disposition == TyposquattingDisposition.LikelyImpersonation)
            .OrderByDescending(candidate => candidate.RiskScore)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Domain)
            .ToList();
        var topClusters = analysis.InfrastructureClusters
            .OrderByDescending(cluster => cluster.Domains.Count)
            .ThenByDescending(cluster => cluster.HighestRiskScore)
            .ThenBy(cluster => cluster.Label, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .Select(cluster => $"{cluster.Label} ({cluster.Domains.Count})")
            .ToList();
        var topCampaigns = analysis.InfrastructureCampaigns
            .OrderByDescending(campaign => campaign.ActionabilityScore)
            .ThenByDescending(campaign => campaign.CampaignScore)
            .ThenByDescending(campaign => campaign.CandidateCount)
            .ThenBy(campaign => campaign.Label, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .Select(campaign => $"{campaign.Label} ({campaign.Severity}, {campaign.Actionability} actionability {campaign.ActionabilityScore}, {campaign.CandidateCount}, top {campaign.TopCandidateDomain}, {campaign.PivotSummary})")
            .ToList();
        var topCampaignActions = analysis.InfrastructureCampaigns
            .OrderByDescending(campaign => campaign.ActionabilityScore)
            .ThenByDescending(campaign => campaign.CampaignScore)
            .ThenByDescending(campaign => campaign.CandidateCount)
            .ThenBy(campaign => campaign.Label, StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .Where(campaign => !string.IsNullOrWhiteSpace(campaign.RecommendedAction))
            .Select(campaign => campaign.Label + ": " + campaign.ActionabilitySummary + "; " + campaign.RecommendedAction)
            .ToList();
        var topCampaignEscalations = analysis.InfrastructureCampaigns
            .OrderByDescending(campaign => campaign.ActionabilityScore)
            .ThenByDescending(campaign => campaign.CampaignScore)
            .ThenByDescending(campaign => campaign.CandidateCount)
            .ThenBy(campaign => campaign.Label, StringComparer.OrdinalIgnoreCase)
            .Take(3)
            .Where(campaign => !string.IsNullOrWhiteSpace(campaign.EscalationBundle.Summary))
            .Select(campaign => campaign.Label + ": " + campaign.EscalationBundle.Summary)
            .ToList();
        var topCampaignDrafts = analysis.InfrastructureCampaigns
            .OrderByDescending(campaign => campaign.ActionabilityScore)
            .ThenByDescending(campaign => campaign.CampaignScore)
            .ThenByDescending(campaign => campaign.CandidateCount)
            .ThenBy(campaign => campaign.Label, StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .Where(campaign => !string.IsNullOrWhiteSpace(campaign.EscalationBundle.DraftPreview))
            .Select(campaign => campaign.Label + ": " + campaign.EscalationBundle.DraftPreview)
            .ToList();
        var topCampaignTracking = analysis.InfrastructureCampaigns
            .OrderByDescending(campaign => campaign.ActionabilityScore)
            .ThenByDescending(campaign => campaign.CampaignScore)
            .ThenByDescending(campaign => campaign.CandidateCount)
            .ThenBy(campaign => campaign.Label, StringComparer.OrdinalIgnoreCase)
            .Take(3)
            .Where(campaign => !string.IsNullOrWhiteSpace(campaign.EscalationBundle.TrackingSummary))
            .Select(campaign => campaign.Label + ": " + campaign.EscalationBundle.TrackingSummary)
            .ToList();
        var highPriorityCampaigns = analysis.InfrastructureCampaigns
            .Count(campaign => campaign.RequiresUrgentReview);
        var criticalCampaigns = analysis.InfrastructureCampaigns
            .Count(campaign => campaign.Severity == TyposquattingInfrastructureCampaignSeverity.Critical);

        hi.Add($"{analysis.Candidates.Count} candidate variants generated.");
        if (active.Count > 0)
        {
            hi.Add($"Active typosquat domains: {string.Join(", ", active)}");
            det.AddRange(active.Select(d => $"Active: {d}"));
        }
        else
        {
            hi.Add("No active typosquat domains detected.");
        }

        if (registered.Count > 0)
        {
            hi.Add($"{registered.Count} variants show a DNS footprint.");
            det.Add("Registered or delegated: " + string.Join(", ", registered.Take(20)));
        }

        if (analysis.SourceOwnershipProfile?.HasAnySignals == true)
        {
            hi.Add($"{likelyExternal.Count} variants look externally distinct from the source estate.");
            hi.Add($"{likelyOwned.Count} variants overlap with source ownership signals.");
            if (likelyExternal.Count > 0)
            {
                det.Add("Most distinct external lookalikes: " + string.Join(", ", likelyExternal.Take(20)));
            }
            if (likelyOwned.Count > 0)
            {
                det.Add("Likely ours or defensively owned: " + string.Join(", ", likelyOwned.Take(20)));
            }
        }

        if (analysis.SourceContentProfile?.HasAnySignals == true)
        {
            hi.Add($"{likelyImpersonating.Count} variants show meaningful source-site content similarity.");
            if (likelyImpersonating.Count > 0)
            {
                det.Add("Most convincing content lookalikes: " + string.Join(", ", likelyImpersonating.Take(20)));
            }
        }

        if (analysis.SourceVisualProfile?.HasAnySignals == true)
        {
            hi.Add($"{likelyVisualClones.Count} variants show strong visual similarity to the source site.");
            if (likelyVisualClones.Count > 0)
            {
                det.Add("Most convincing visual lookalikes: " + string.Join(", ", likelyVisualClones.Take(20)));
            }
        }

        hi.Add($"{mailEnabled.Count} variants expose responsive MX infrastructure over SMTP.");
        if (mailEnabled.Count > 0)
        {
            det.Add("Mail-enabled typo domains: " + string.Join(", ", mailEnabled.Take(20)));
        }
        hi.Add($"{mailAccepting.Count} variants appear able to receive mail for the lookalike domain.");
        if (mailAccepting.Count > 0)
        {
            det.Add("Mail-accepting typo domains: " + string.Join(", ", mailAccepting.Take(20)));
        }

        hi.Add($"{analysis.InfrastructureClusters.Count} external infrastructure clusters were identified across the candidate set.");
        if (topClusters.Count > 0)
        {
            det.Add("Top shared infrastructure clusters: " + string.Join(", ", topClusters));
        }

        hi.Add($"{highPriorityCampaigns} shared-infrastructure campaigns warrant urgent review, including {criticalCampaigns} critical campaigns.");
        if (topCampaigns.Count > 0)
        {
            det.Add("Top hostile campaigns: " + string.Join(", ", topCampaigns));
        }
        if (topCampaignActions.Count > 0)
        {
            det.Add("Campaign actions: " + string.Join(", ", topCampaignActions));
        }

        if (topCampaignEscalations.Count > 0)
        {
            det.Add("Escalation bundles ready: " + string.Join(", ", topCampaignEscalations));
        }
        if (topCampaignDrafts.Count > 0)
        {
            det.Add("Outreach drafts ready: " + string.Join(", ", topCampaignDrafts));
        }
        if (topCampaignTracking.Count > 0)
        {
            det.Add("Campaign case tracking: " + string.Join(", ", topCampaignTracking));
        }

        hi.Add($"{likelyMalicious.Count} variants look likely malicious based on combined external, impersonation, and activity signals.");
        hi.Add($"{likelyImpersonation.Count} variants look like likely impersonators that warrant urgent review.");
        if (likelyMalicious.Count > 0)
        {
            det.Add("Highest-priority likely malicious variants: " + string.Join(", ", likelyMalicious.Take(20)));
        }
        if (likelyImpersonation.Count > 0)
        {
            det.Add("Likely impersonation variants: " + string.Join(", ", likelyImpersonation.Take(20)));
        }

        var topKinds = analysis.Candidates
            .GroupBy(candidate => candidate.Kind)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .Select(group => $"{group.Key}: {group.Count()}")
            .ToList();
        if (topKinds.Count > 0)
        {
            det.Add("Top variant families: " + string.Join(", ", topKinds));
        }

        var available = (analysis.Variants ?? new List<string>())
            .Except(active, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (available.Count > 0)
        {
            det.Add("Available for defensive registration: " + string.Join(", ", available));
        }

        var refs = new List<string>
        {
            "https://en.wikipedia.org/wiki/Typosquatting"
        };

        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();
        try
        {
            var groups = RecommendationEngine.GroupByCode(analysis.Assessments ?? new List<Assessment>());
            foreach (var g in groups)
            {
                var adviceTitle = g.Advice?.Title;
                string msg;
                if (adviceTitle != null && !string.IsNullOrWhiteSpace(adviceTitle))
                {
                    msg = adviceTitle;
                }
                else
                {
                    msg = g.Instances.FirstOrDefault()?.Message ?? g.Code;
                }
                if (g.MaxSeverity == AssessmentSeverity.Info)
                {
                    positives.Add(msg);
                }
                else
                {
                    negatives.Add(msg);
                    remediations.Add(msg);
                }
            }
        }
        catch { }

        return new Sections
        {
            Title = title,
            Subtitle = subtitle,
            Category = category,
            Keywords = keywords,
            Creator = creator,
            Introduction = intro,
            WhyItMatters = why,
            Highlights = hi,
            Details = det,
            References = refs,
            Positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private static string DescribeVisualMatch(TyposquattingVisualSimilarityMatch? match)
    {
        if (match == null)
        {
            return "visual asset";
        }

        return match.MatchedArtifactKind switch
        {
            TyposquattingVisualArtifactKind.Screenshot => "rendered page",
            TyposquattingVisualArtifactKind.OpenGraphImage => "og:image",
            TyposquattingVisualArtifactKind.TwitterImage => "twitter:image",
            TyposquattingVisualArtifactKind.AppleTouchIcon => "apple-touch-icon",
            TyposquattingVisualArtifactKind.Favicon => "favicon",
            _ => "visual asset"
        };
    }
}
