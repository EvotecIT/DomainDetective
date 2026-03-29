using System;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public static TyposquattingSection? BuildTyposquatting(DomainDetective.Views.TyposquattingInfo info)
    {
        if (info == null)
        {
            return null;
        }

        var section = new TyposquattingSection
        {
            Status = info.Status ?? "-",
            CandidateCount = info.CandidateCount,
            ActiveCount = info.ActiveCount,
            RegisteredCount = info.RegisteredCount,
            EnrichedCount = info.EnrichedCandidateCount,
            ReachableWebCount = info.ReachableWebCount,
            ThreatListedCount = info.ThreatListedCount,
            HighRiskCount = info.HighRiskCount,
            LikelyOwnedCount = info.LikelyOwnedCount,
            LikelyExternalCount = info.LikelyExternalCount,
            OwnershipProfileBuilt = info.OwnershipProfileBuilt,
            LikelyImpersonatingCount = info.LikelyImpersonatingCount,
            ContentProfileBuilt = info.ContentProfileBuilt,
            LikelyVisualCloneCount = info.LikelyVisualCloneCount,
            VisualProfileBuilt = info.VisualProfileBuilt,
            ClusteredCandidateCount = info.ClusteredCandidateCount,
            InfrastructureClusterCount = info.InfrastructureClusterCount,
            MultiCandidateInfrastructureClusterCount = info.MultiCandidateInfrastructureClusterCount,
            LargestInfrastructureClusterSize = info.LargestInfrastructureClusterSize,
            HighPriorityCampaignCount = info.HighPriorityCampaignCount,
            CriticalCampaignCount = info.CriticalCampaignCount,
            AvailableCount = info.AvailableCount,
            DefensiveOwnedDispositionCount = info.DefensiveOwnedDispositionCount,
            MonitorCount = info.MonitorCount,
            LikelyImpersonationDispositionCount = info.LikelyImpersonationDispositionCount,
            LikelyMaliciousCount = info.LikelyMaliciousCount,
            ContainsHomoglyphs = info.ContainsHomoglyphs
        };

        section.Summary.Add(("Status", section.Status));
        section.Summary.Add(("Candidates", section.CandidateCount.ToString()));
        section.Summary.Add(("Active", section.ActiveCount.ToString()));
        section.Summary.Add(("Registered", section.RegisteredCount.ToString()));
        section.Summary.Add(("Enriched", section.EnrichedCount.ToString()));
        section.Summary.Add(("HTTP Reachable", section.ReachableWebCount.ToString()));
        section.Summary.Add(("Threat Listed", section.ThreatListedCount.ToString()));
        section.Summary.Add(("High Risk", section.HighRiskCount.ToString()));
        section.Summary.Add(("Likely Impersonating", section.LikelyImpersonatingCount.ToString()));
        section.Summary.Add(("Likely Visual Clone", section.LikelyVisualCloneCount.ToString()));
        section.Summary.Add(("Likely External", section.LikelyExternalCount.ToString()));
        section.Summary.Add(("Likely Owned", section.LikelyOwnedCount.ToString()));
        section.Summary.Add(("Infrastructure Clusters", section.InfrastructureClusterCount.ToString()));
        section.Summary.Add(("Shared Clusters", section.MultiCandidateInfrastructureClusterCount.ToString()));
        section.Summary.Add(("Clustered Candidates", section.ClusteredCandidateCount.ToString()));
        section.Summary.Add(("Largest Cluster", section.LargestInfrastructureClusterSize.ToString()));
        section.Summary.Add(("High-Priority Campaigns", section.HighPriorityCampaignCount.ToString()));
        section.Summary.Add(("Critical Campaigns", section.CriticalCampaignCount.ToString()));
        section.Summary.Add(("Likely Malicious", section.LikelyMaliciousCount.ToString()));
        section.Summary.Add(("Likely Impersonation", section.LikelyImpersonationDispositionCount.ToString()));
        section.Summary.Add(("Monitor", section.MonitorCount.ToString()));
        section.Summary.Add(("Defensive Owned", section.DefensiveOwnedDispositionCount.ToString()));
        section.Summary.Add(("Available", section.AvailableCount.ToString()));
        section.Summary.Add(("Ownership Profile", section.OwnershipProfileBuilt ? "Built" : "Not Built"));
        section.Summary.Add(("Content Profile", section.ContentProfileBuilt ? "Built" : "Not Built"));
        section.Summary.Add(("Visual Profile", section.VisualProfileBuilt ? "Built" : "Not Built"));
        section.Summary.Add(("Homoglyph Input", section.ContainsHomoglyphs ? "Yes" : "No"));

        foreach (var candidate in info.Candidates ?? Array.Empty<DomainDetective.Views.TyposquattingCandidateInfo>())
        {
            section.Rows.Add(new TyposquattingSection.Row
            {
                Domain = candidate.Domain,
                Kind = candidate.Kind,
                EditDistance = candidate.EditDistance,
                Resolves = candidate.Resolves,
                AppearsRegistered = candidate.AppearsRegistered,
                RiskScore = candidate.RiskScore,
                RiskLevel = candidate.RiskLevel,
                RiskSummary = candidate.RiskSummary,
                Disposition = candidate.Disposition,
                DispositionSummary = candidate.DispositionSummary,
                InfrastructureClusterLabel = candidate.InfrastructureClusterLabel,
                InfrastructureClusterSize = candidate.InfrastructureClusterSize,
                InfrastructureClusterSummary = candidate.InfrastructureClusterSummary,
                ACount = candidate.ACount,
                AaaaCount = candidate.AaaaCount,
                NsCount = candidate.NsCount,
                MxCount = candidate.MxCount,
                Registrar = candidate.Registrar ?? string.Empty,
                HttpStatusCode = candidate.HttpStatusCode,
                ThreatListed = candidate.ThreatListed,
                TechnologyCount = candidate.TechnologyCount,
                EnrichedIpCount = candidate.EnrichedIpCount,
                LikelyOwned = candidate.LikelyOwned,
                OwnershipConfidence = candidate.OwnershipConfidence,
                OwnershipSummary = candidate.OwnershipSummary,
                LikelyExternal = candidate.LikelyExternal,
                ExternalConfidence = candidate.ExternalConfidence,
                ExternalSummary = candidate.ExternalSummary,
                ContentSimilarityScore = candidate.ContentSimilarityScore,
                LikelyImpersonating = candidate.LikelyImpersonating,
                ContentSimilaritySummary = candidate.ContentSimilaritySummary,
                VisualSimilarityScore = candidate.VisualSimilarityScore,
                LikelyVisualClone = candidate.LikelyVisualClone,
                VisualSimilarityDistance = candidate.VisualSimilarityDistance,
                VisualMatchKind = candidate.VisualMatchKind,
                VisualMatchType = NormalizeVisualMatchType(candidate.VisualMatchKind),
                VisualMatchedSourceUrl = candidate.VisualMatchedSourceUrl,
                VisualCandidateArtifactUrl = candidate.VisualCandidateArtifactUrl,
                VisualSimilaritySummary = candidate.VisualSimilaritySummary,
                EnrichmentSummary = candidate.Enrichment?.Summary ?? string.Empty
            });
        }

        foreach (var assessment in info.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (assessment != null && assessment.Severity != DomainDetective.AssessmentSeverity.Info)
            {
                section.Findings.Add(new SimpleFinding(
                    assessment.Severity.ToString(),
                    assessment.Code ?? string.Empty,
                    assessment.Target ?? string.Empty,
                    assessment.Message ?? string.Empty));
            }
        }

        foreach (var positive in info.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var title = positive?.Title ?? positive?.Code;
            if (!string.IsNullOrWhiteSpace(title))
            {
                section.Positives.Add(title!);
            }
        }

        foreach (var reference in info.References ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(reference))
            {
                section.References.Add(reference);
            }
        }

        foreach (var campaign in info.Campaigns ?? Array.Empty<DomainDetective.Views.TyposquattingCampaignInfo>())
        {
            section.Campaigns.Add(new TyposquattingSection.CampaignRow
            {
                Label = campaign.Label,
                Severity = campaign.Severity,
                CampaignScore = campaign.CampaignScore,
                CandidateCount = campaign.CandidateCount,
                ActiveCount = campaign.ActiveCount,
                ReachableWebCount = campaign.ReachableWebCount,
                ThreatListedCount = campaign.ThreatListedCount,
                LikelyMaliciousCount = campaign.LikelyMaliciousCount,
                LikelyImpersonationCount = campaign.LikelyImpersonationCount,
                LikelyImpersonatingCount = campaign.LikelyImpersonatingCount,
                LikelyVisualCloneCount = campaign.LikelyVisualCloneCount,
                HighestRiskScore = campaign.HighestRiskScore,
                TopCandidateDomain = campaign.TopCandidateDomain,
                TopCandidateDisposition = campaign.TopCandidateDisposition,
                Summary = campaign.Summary,
                PivotSummary = campaign.PivotSummary,
                PrimaryRegistrar = campaign.PrimaryRegistrar,
                RegistrarConcentrationPercent = campaign.RegistrarConcentrationPercent,
                PrimaryHostingProvider = campaign.PrimaryHostingProvider,
                HostingConcentrationPercent = campaign.HostingConcentrationPercent,
                PrimaryCountry = campaign.PrimaryCountry,
                CountryConcentrationPercent = campaign.CountryConcentrationPercent,
                PrimaryAbuseContact = campaign.PrimaryAbuseContact,
                ActionabilityScore = campaign.ActionabilityScore,
                Actionability = campaign.Actionability,
                ActionabilitySummary = campaign.ActionabilitySummary,
                RecommendedAction = campaign.RecommendedAction,
                EscalationCaseId = campaign.EscalationCaseId,
                EscalationTrackingSummary = campaign.EscalationTrackingSummary,
                EscalationDraftPreview = campaign.EscalationDraftPreview,
                EscalationSummary = campaign.EscalationSummary
            });
        }

        var topCampaign = section.Campaigns
            .OrderByDescending(static campaign => campaign.ActionabilityScore)
            .ThenByDescending(static campaign => campaign.CampaignScore)
            .ThenByDescending(static campaign => campaign.CandidateCount)
            .ThenBy(static campaign => campaign.Label, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (topCampaign != null)
        {
            section.TopResponsePack = new TyposquattingSection.ResponsePack
            {
                Label = topCampaign.Label,
                Severity = topCampaign.Severity,
                CaseId = topCampaign.EscalationCaseId,
                TopDomain = topCampaign.TopCandidateDomain,
                PrimaryContact = topCampaign.PrimaryAbuseContact,
                TrackingSummary = topCampaign.EscalationTrackingSummary,
                EscalationSummary = topCampaign.EscalationSummary,
                ActionabilitySummary = topCampaign.ActionabilitySummary,
                RecommendedAction = topCampaign.RecommendedAction,
                DraftPreview = topCampaign.EscalationDraftPreview
            };
        }

        return section;
    }

    private static string NormalizeVisualMatchType(string? kind)
    {
        if (string.IsNullOrWhiteSpace(kind))
        {
            return string.Empty;
        }

        return kind switch
        {
            nameof(DomainDetective.TyposquattingVisualArtifactKind.Screenshot) => "Rendered Page",
            nameof(DomainDetective.TyposquattingVisualArtifactKind.OpenGraphImage) => "OG Image",
            nameof(DomainDetective.TyposquattingVisualArtifactKind.TwitterImage) => "Twitter Image",
            nameof(DomainDetective.TyposquattingVisualArtifactKind.AppleTouchIcon) => "Touch Icon",
            nameof(DomainDetective.TyposquattingVisualArtifactKind.Favicon) => "Favicon",
            _ => kind!
        };
    }
}
