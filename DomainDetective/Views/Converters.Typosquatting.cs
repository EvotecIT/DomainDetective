using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static TyposquattingInfo Convert(TyposquattingAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var candidates = analysis.Candidates?
            .Select(candidate => new TyposquattingCandidateInfo
            {
                Domain = candidate.Domain,
                Kind = candidate.Kind.ToString(),
                EditDistance = candidate.EditDistance,
                Resolves = candidate.Resolves,
                AppearsRegistered = candidate.AppearsRegistered,
                RiskScore = candidate.RiskScore,
                RiskLevel = candidate.RiskLevel.ToString(),
                RiskSummary = candidate.RiskSummary,
                RiskReasons = candidate.RiskReasons,
                Disposition = candidate.Disposition.ToString(),
                DispositionSummary = candidate.DispositionSummary,
                DispositionReasons = candidate.DispositionReasons,
                InfrastructureClusterId = candidate.InfrastructureCluster?.Id ?? string.Empty,
                InfrastructureClusterLabel = candidate.InfrastructureCluster?.Label ?? string.Empty,
                InfrastructureClusterSize = candidate.InfrastructureCluster?.Domains.Count ?? 0,
                InfrastructureClusterSummary = candidate.InfrastructureCluster == null
                    ? string.Empty
                    : string.Join(", ", candidate.InfrastructureCluster.SharedSignals),
                ACount = candidate.ARecords.Count,
                AaaaCount = candidate.AaaaRecords.Count,
                NsCount = candidate.NsRecords.Count,
                MxCount = candidate.MxRecords.Count,
                Registrar = candidate.Enrichment?.Whois?.Registrar,
                HttpReachable = candidate.Enrichment?.Http?.IsReachable == true,
                HttpStatusCode = candidate.Enrichment?.Http?.StatusCode,
                ThreatListed = candidate.Enrichment?.ThreatIntel?.Listings?.Any(listing => listing.IsListed) == true,
                ThreatSeverity = candidate.Enrichment?.ThreatIntel?.Severity,
                TechnologyCount = candidate.Enrichment?.WebStaticScan?.TechDetections?.Count ?? 0,
                EnrichedIpCount = candidate.Enrichment?.IpEnrichment?.UniqueIpCount ?? 0,
                SmtpBannerReachable = candidate.Enrichment?.SmtpBanner?.ServerResults?.Any(result => result.Value?.StartsWith220 == true) == true,
                SmtpRecipientAccepted = candidate.Enrichment?.SmtpRecipientAcceptance?.ServerResults?.Any(result => result.Value?.Accepted == true) == true,
                PrimaryMxHost = TyposquattingMailInfrastructure.NormalizeMxHosts(candidate.MxRecords).FirstOrDefault() ?? string.Empty,
                SmtpBannerSummary = BuildSmtpBannerSummary(candidate.Enrichment?.SmtpBanner),
                SmtpRecipientAcceptanceSummary = BuildSmtpRecipientAcceptanceSummary(candidate.Enrichment?.SmtpRecipientAcceptance),
                LikelyOwned = candidate.Ownership?.LikelyOwned == true,
                OwnershipConfidence = candidate.Ownership?.ConfidenceScore ?? 0,
                OwnershipSummary = candidate.Ownership?.Summary ?? string.Empty,
                OwnershipSignals = candidate.Ownership?.Signals ?? System.Array.Empty<string>(),
                LikelyExternal = candidate.Ownership?.LikelyExternal == true,
                ExternalConfidence = candidate.Ownership?.ExternalConfidenceScore ?? 0,
                ExternalSummary = candidate.Ownership?.ExternalSummary ?? string.Empty,
                ExternalSignals = candidate.Ownership?.ExternalSignals ?? System.Array.Empty<string>(),
                ContentSimilarityScore = candidate.ContentSimilarity?.Score ?? 0,
                LikelyImpersonating = candidate.ContentSimilarity?.LikelyImpersonating == true,
                ContentFingerprintSimilarity = candidate.ContentSimilarity?.FuzzyFingerprintSimilarity,
                ContentFingerprintDistance = candidate.ContentSimilarity?.FuzzyFingerprintDistance,
                ContentSimilaritySummary = candidate.ContentSimilarity?.Summary ?? string.Empty,
                ContentSimilaritySignals = candidate.ContentSimilarity?.Signals ?? System.Array.Empty<string>(),
                VisualSimilarityScore = candidate.VisualSimilarity?.Score ?? 0,
                LikelyVisualClone = candidate.VisualSimilarity?.LikelyClone == true,
                VisualSimilarityDistance = candidate.VisualSimilarity?.HammingDistance,
                VisualMatchKind = candidate.VisualSimilarity?.MatchedArtifactKind.ToString() ?? string.Empty,
                VisualMatchedSourceUrl = candidate.VisualSimilarity?.MatchedSourceUrl ?? string.Empty,
                VisualCandidateArtifactUrl = candidate.VisualSimilarity?.CandidateArtifactUrl ?? string.Empty,
                VisualSimilaritySummary = candidate.VisualSimilarity?.Summary ?? string.Empty,
                VisualSimilaritySignals = candidate.VisualSimilarity?.Signals ?? System.Array.Empty<string>(),
                Enrichment = candidate.Enrichment == null
                    ? null
                    : new TyposquattingCandidateEnrichmentInfo
                    {
                        Whois = candidate.Enrichment.Whois == null ? null : Convert(candidate.Enrichment.Whois),
                        Http = candidate.Enrichment.Http == null ? null : Convert(candidate.Enrichment.Http),
                        ThreatIntel = candidate.Enrichment.ThreatIntel == null ? null : Convert(candidate.Enrichment.ThreatIntel),
                        WebStaticScan = candidate.Enrichment.WebStaticScan == null ? null : Convert(candidate.Enrichment.WebStaticScan),
                        IpEnrichment = candidate.Enrichment.IpEnrichment == null ? null : Convert(candidate.Enrichment.IpEnrichment),
                        SmtpBannerSummary = BuildSmtpBannerSummary(candidate.Enrichment.SmtpBanner),
                        SmtpRecipientAcceptanceSummary = BuildSmtpRecipientAcceptanceSummary(candidate.Enrichment.SmtpRecipientAcceptance),
                        Summary = BuildEnrichmentSummary(candidate.Enrichment)
                    }
            })
            .ToArray() ?? System.Array.Empty<TyposquattingCandidateInfo>();
        var kindCounts = candidates
            .GroupBy(candidate => candidate.Kind, System.StringComparer.OrdinalIgnoreCase)
            .Select(group => new TyposquattingKindCount { Kind = group.Key, Count = group.Count() })
            .OrderByDescending(group => group.Count)
            .ThenBy(group => group.Kind, System.StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var campaigns = analysis.InfrastructureCampaigns
            .Select(campaign => new TyposquattingCampaignInfo
            {
                Id = campaign.Id,
                Label = campaign.Label,
                Severity = campaign.Severity.ToString(),
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
                PrimaryRegistrar = campaign.PrimaryRegistrar,
                RegistrarConcentrationPercent = campaign.RegistrarConcentrationPercent,
                PrimaryHostingProvider = campaign.PrimaryHostingProvider,
                HostingConcentrationPercent = campaign.HostingConcentrationPercent,
                PrimaryCountry = campaign.PrimaryCountry,
                CountryConcentrationPercent = campaign.CountryConcentrationPercent,
                PrimaryAbuseContact = campaign.PrimaryAbuseContact,
                ActionabilityScore = campaign.ActionabilityScore,
                Actionability = campaign.Actionability.ToString(),
                ActionabilitySummary = campaign.ActionabilitySummary,
                AbuseContacts = campaign.AbuseContacts,
                RegistrarContacts = campaign.RegistrarContacts,
                HostingProviders = campaign.HostingProviders,
                Countries = campaign.Countries,
                EscalationSubject = campaign.EscalationBundle.Subject,
                EscalationCaseId = campaign.EscalationBundle.CaseId,
                EscalationCaseFingerprint = campaign.EscalationBundle.CaseFingerprint,
                EscalationTrackingSummary = campaign.EscalationBundle.TrackingSummary,
                EscalationSummary = campaign.EscalationBundle.Summary,
                EscalationEvidenceSummary = campaign.EscalationBundle.EvidenceSummary,
                EscalationDraftPreview = campaign.EscalationBundle.DraftPreview,
                EscalationDraftBody = campaign.EscalationBundle.DraftBody,
                EscalationPrimaryRoute = campaign.EscalationBundle.PrimaryRoute.ToString(),
                EscalationPrimaryContact = campaign.EscalationBundle.PrimaryContact,
                EscalationContacts = campaign.EscalationBundle.Contacts,
                EscalationDomains = campaign.EscalationBundle.Domains,
                EscalationEvidencePoints = campaign.EscalationBundle.EvidencePoints,
                EscalationChecklist = campaign.EscalationBundle.ActionChecklist,
                Summary = campaign.Summary,
                PivotSummary = campaign.PivotSummary,
                RecommendedAction = campaign.RecommendedAction,
                SharedSignals = campaign.SharedSignals,
                Domains = campaign.Domains
            })
            .ToArray();
        var topResponsePack = campaigns
            .OrderByDescending(static campaign => campaign.ActionabilityScore)
            .ThenByDescending(static campaign => campaign.CampaignScore)
            .ThenByDescending(static campaign => campaign.CandidateCount)
            .ThenBy(static campaign => campaign.Label, System.StringComparer.OrdinalIgnoreCase)
            .Select(static campaign => new TyposquattingResponsePackInfo
            {
                Campaign = campaign.Label,
                Severity = campaign.Severity,
                CaseId = campaign.EscalationCaseId,
                CaseFingerprint = campaign.EscalationCaseFingerprint,
                TopDomain = campaign.TopCandidateDomain,
                PrimaryContact = campaign.EscalationPrimaryContact,
                TrackingSummary = campaign.EscalationTrackingSummary,
                EscalationSummary = campaign.EscalationSummary,
                ActionabilitySummary = campaign.ActionabilitySummary,
                RecommendedAction = campaign.RecommendedAction,
                DraftPreview = campaign.EscalationDraftPreview,
                DraftBody = campaign.EscalationDraftBody
            })
            .FirstOrDefault();
        candidates = candidates
            .OrderByDescending(candidate => candidate.RiskScore)
            .ThenByDescending(candidate => candidate.Resolves)
            .ThenByDescending(candidate => candidate.AppearsRegistered)
            .ThenBy(candidate => candidate.Domain, System.StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var enrichedCount = candidates.Count(candidate => candidate.Enrichment != null);
        var reachableWebCount = candidates.Count(candidate => candidate.HttpReachable);
        var threatListedCount = candidates.Count(candidate => candidate.ThreatListed);
        var highRiskCount = candidates.Count(candidate => string.Equals(candidate.RiskLevel, TyposquattingRiskLevel.High.ToString(), System.StringComparison.OrdinalIgnoreCase)
            || string.Equals(candidate.RiskLevel, TyposquattingRiskLevel.Critical.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var likelyOwnedCount = candidates.Count(candidate => candidate.LikelyOwned);
        var likelyExternalCount = candidates.Count(candidate => candidate.LikelyExternal);
        var likelyImpersonatingCount = candidates.Count(candidate => candidate.LikelyImpersonating);
        var likelyVisualCloneCount = candidates.Count(candidate => candidate.LikelyVisualClone);
        var clusteredCandidateCount = candidates.Count(candidate => candidate.InfrastructureClusterSize > 0);
        var clusterCount = analysis.InfrastructureClusters.Count;
        var multiCandidateClusterCount = analysis.InfrastructureClusters.Count(cluster => cluster.HasMultipleCandidates);
        var largestClusterSize = analysis.InfrastructureClusters.Count > 0 ? analysis.InfrastructureClusters.Max(cluster => cluster.Domains.Count) : 0;
        var highPriorityCampaignCount = campaigns.Count(campaign =>
            string.Equals(campaign.Severity, TyposquattingInfrastructureCampaignSeverity.High.ToString(), System.StringComparison.OrdinalIgnoreCase)
            || string.Equals(campaign.Severity, TyposquattingInfrastructureCampaignSeverity.Critical.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var criticalCampaignCount = campaigns.Count(campaign =>
            string.Equals(campaign.Severity, TyposquattingInfrastructureCampaignSeverity.Critical.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var availableCount = candidates.Count(candidate => string.Equals(candidate.Disposition, TyposquattingDisposition.Available.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var defensiveOwnedCount = candidates.Count(candidate => string.Equals(candidate.Disposition, TyposquattingDisposition.DefensiveOwned.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var monitorCount = candidates.Count(candidate => string.Equals(candidate.Disposition, TyposquattingDisposition.Monitor.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var likelyImpersonationDispositionCount = candidates.Count(candidate => string.Equals(candidate.Disposition, TyposquattingDisposition.LikelyImpersonation.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var likelyMaliciousCount = candidates.Count(candidate => string.Equals(candidate.Disposition, TyposquattingDisposition.LikelyMalicious.ToString(), System.StringComparison.OrdinalIgnoreCase));
        var ownershipProfileBuilt = analysis.SourceOwnershipProfile?.HasAnySignals == true;
        var contentProfileBuilt = analysis.SourceContentProfile?.HasAnySignals == true;
        var visualProfileBuilt = analysis.SourceVisualProfile?.HasAnySignals == true;

        return new TyposquattingInfo
        {
            Check = HealthCheckType.TYPOSQUATTING,
            Area = AreaForKind(HealthCheckType.TYPOSQUATTING),
            Subject = analysis.Subject,
            CandidateCount = candidates.Length,
            ActiveCount = analysis.ActiveDomains.Count,
            RegisteredCount = analysis.RegisteredDomains.Count,
            ContainsHomoglyphs = analysis.ContainsHomoglyphs,
            KindCounts = kindCounts,
            Candidates = candidates,
            EnrichedCandidateCount = enrichedCount,
            ReachableWebCount = reachableWebCount,
            ThreatListedCount = threatListedCount,
            HighRiskCount = highRiskCount,
            LikelyOwnedCount = likelyOwnedCount,
            LikelyExternalCount = likelyExternalCount,
            OwnershipProfileBuilt = ownershipProfileBuilt,
            LikelyImpersonatingCount = likelyImpersonatingCount,
            ContentProfileBuilt = contentProfileBuilt,
            LikelyVisualCloneCount = likelyVisualCloneCount,
            VisualProfileBuilt = visualProfileBuilt,
            ClusteredCandidateCount = clusteredCandidateCount,
            InfrastructureClusterCount = clusterCount,
            MultiCandidateInfrastructureClusterCount = multiCandidateClusterCount,
            LargestInfrastructureClusterSize = largestClusterSize,
            Campaigns = campaigns,
            TopResponsePack = topResponsePack,
            HighPriorityCampaignCount = highPriorityCampaignCount,
            CriticalCampaignCount = criticalCampaignCount,
            AvailableCount = availableCount,
            DefensiveOwnedDispositionCount = defensiveOwnedCount,
            MonitorCount = monitorCount,
            LikelyImpersonationDispositionCount = likelyImpersonationDispositionCount,
            LikelyMaliciousCount = likelyMaliciousCount,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{analysis.ActiveDomains.Count} active; {analysis.RegisteredDomains.Count} registered; {candidates.Length} candidates; {campaigns.Length} campaigns; {highPriorityCampaignCount} high-priority campaigns; {likelyMaliciousCount} likely-malicious; {likelyImpersonationDispositionCount} likely-impersonating; {monitorCount} monitor; {defensiveOwnedCount} defensively-owned; {availableCount} available; {enrichedCount} enriched",
            Recommendations = recs,
            Positives = positives,
            References = new[] { "https://en.wikipedia.org/wiki/Typosquatting" },
            Raw = analysis
        };
    }

    private static string BuildEnrichmentSummary(TyposquattingCandidateEnrichment enrichment)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(enrichment.Whois?.Registrar))
        {
            parts.Add("WHOIS");
        }
        if (enrichment.Http?.IsReachable == true)
        {
            parts.Add("HTTP");
        }
        if (enrichment.WebStaticScan?.TechDetections?.Count > 0)
        {
            parts.Add("WEB");
        }
        if (enrichment.ThreatIntel?.Listings?.Any(listing => listing.IsListed) == true)
        {
            parts.Add("THREAT");
        }
        if ((enrichment.IpEnrichment?.UniqueIpCount ?? 0) > 0)
        {
            parts.Add("IP");
        }
        if (enrichment.SmtpBanner?.ServerResults?.Any(static result => result.Value?.StartsWith220 == true) == true)
        {
            parts.Add("SMTP");
        }
        if (enrichment.SmtpRecipientAcceptance?.ServerResults?.Any(static result => result.Value?.Accepted == true) == true)
        {
            parts.Add("SMTP-RCPT");
        }

        return parts.Count > 0 ? string.Join(", ", parts) : "Enriched";
    }

    private static string BuildSmtpBannerSummary(SMTPBannerAnalysis? analysis)
    {
        if (analysis?.ServerResults == null || analysis.ServerResults.Count == 0)
        {
            return string.Empty;
        }

        var firstResponsive = analysis.ServerResults
            .OrderBy(static result => result.Key, System.StringComparer.OrdinalIgnoreCase)
            .Select(static result => result.Value)
            .FirstOrDefault(static result => result?.StartsWith220 == true && !string.IsNullOrWhiteSpace(result.Host));
        if (firstResponsive == null)
        {
            return string.Empty;
        }

        return firstResponsive.Host + (string.IsNullOrWhiteSpace(firstResponsive.Banner) ? string.Empty : ": " + firstResponsive.Banner);
    }

    private static string BuildSmtpRecipientAcceptanceSummary(SmtpRecipientAcceptanceAnalysis? analysis)
    {
        if (analysis?.ServerResults == null || analysis.ServerResults.Count == 0)
        {
            return string.Empty;
        }

        var accepted = analysis.ServerResults
            .OrderBy(static result => result.Key, System.StringComparer.OrdinalIgnoreCase)
            .Select(static result => result.Value)
            .FirstOrDefault(static result => result?.Accepted == true && !string.IsNullOrWhiteSpace(result.Host));
        if (accepted == null)
        {
            return string.Empty;
        }

        return accepted.Host + " accepted " + accepted.Recipient;
    }
}

public sealed class TyposquattingInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int CandidateCount { get; set; }
    public int ActiveCount { get; set; }
    public int RegisteredCount { get; set; }
    public bool ContainsHomoglyphs { get; set; }
    public IReadOnlyList<TyposquattingKindCount> KindCounts { get; set; } = System.Array.Empty<TyposquattingKindCount>();
    public IReadOnlyList<TyposquattingCandidateInfo> Candidates { get; set; } = System.Array.Empty<TyposquattingCandidateInfo>();
    public int EnrichedCandidateCount { get; set; }
    public int ReachableWebCount { get; set; }
    public int ThreatListedCount { get; set; }
    public int HighRiskCount { get; set; }
    public int LikelyOwnedCount { get; set; }
    public int LikelyExternalCount { get; set; }
    public bool OwnershipProfileBuilt { get; set; }
    public int LikelyImpersonatingCount { get; set; }
    public bool ContentProfileBuilt { get; set; }
    public int LikelyVisualCloneCount { get; set; }
    public bool VisualProfileBuilt { get; set; }
    public int ClusteredCandidateCount { get; set; }
    public int InfrastructureClusterCount { get; set; }
    public int MultiCandidateInfrastructureClusterCount { get; set; }
    public int LargestInfrastructureClusterSize { get; set; }
    public IReadOnlyList<TyposquattingCampaignInfo> Campaigns { get; set; } = System.Array.Empty<TyposquattingCampaignInfo>();
    public TyposquattingResponsePackInfo? TopResponsePack { get; set; }
    public int HighPriorityCampaignCount { get; set; }
    public int CriticalCampaignCount { get; set; }
    public int AvailableCount { get; set; }
    public int DefensiveOwnedDispositionCount { get; set; }
    public int MonitorCount { get; set; }
    public int LikelyImpersonationDispositionCount { get; set; }
    public int LikelyMaliciousCount { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public TyposquattingAnalysis Raw { get; set; } = null!;
}

public sealed class TyposquattingKindCount
{
    public string Kind { get; set; } = string.Empty;
    public int Count { get; set; }
}

public sealed class TyposquattingResponsePackInfo
{
    public string Campaign { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string CaseId { get; set; } = string.Empty;
    public string CaseFingerprint { get; set; } = string.Empty;
    public string TopDomain { get; set; } = string.Empty;
    public string PrimaryContact { get; set; } = string.Empty;
    public string TrackingSummary { get; set; } = string.Empty;
    public string EscalationSummary { get; set; } = string.Empty;
    public string ActionabilitySummary { get; set; } = string.Empty;
    public string RecommendedAction { get; set; } = string.Empty;
    public string DraftPreview { get; set; } = string.Empty;
    public string DraftBody { get; set; } = string.Empty;
}

public sealed class TyposquattingCampaignInfo
{
    public string Id { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public int CampaignScore { get; set; }
    public int CandidateCount { get; set; }
    public int ActiveCount { get; set; }
    public int ReachableWebCount { get; set; }
    public int ThreatListedCount { get; set; }
    public int LikelyMaliciousCount { get; set; }
    public int LikelyImpersonationCount { get; set; }
    public int LikelyImpersonatingCount { get; set; }
    public int LikelyVisualCloneCount { get; set; }
    public int HighestRiskScore { get; set; }
    public string TopCandidateDomain { get; set; } = string.Empty;
    public string TopCandidateDisposition { get; set; } = string.Empty;
    public string PrimaryRegistrar { get; set; } = string.Empty;
    public int RegistrarConcentrationPercent { get; set; }
    public string PrimaryHostingProvider { get; set; } = string.Empty;
    public int HostingConcentrationPercent { get; set; }
    public string PrimaryCountry { get; set; } = string.Empty;
    public int CountryConcentrationPercent { get; set; }
    public string PrimaryAbuseContact { get; set; } = string.Empty;
    public int ActionabilityScore { get; set; }
    public string Actionability { get; set; } = string.Empty;
    public string ActionabilitySummary { get; set; } = string.Empty;
    public IReadOnlyList<string> AbuseContacts { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> RegistrarContacts { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> HostingProviders { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> Countries { get; set; } = System.Array.Empty<string>();
    public string EscalationSubject { get; set; } = string.Empty;
    public string EscalationCaseId { get; set; } = string.Empty;
    public string EscalationCaseFingerprint { get; set; } = string.Empty;
    public string EscalationTrackingSummary { get; set; } = string.Empty;
    public string EscalationSummary { get; set; } = string.Empty;
    public string EscalationEvidenceSummary { get; set; } = string.Empty;
    public string EscalationDraftPreview { get; set; } = string.Empty;
    public string EscalationDraftBody { get; set; } = string.Empty;
    public string EscalationPrimaryRoute { get; set; } = string.Empty;
    public string EscalationPrimaryContact { get; set; } = string.Empty;
    public IReadOnlyList<string> EscalationContacts { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> EscalationDomains { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> EscalationEvidencePoints { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> EscalationChecklist { get; set; } = System.Array.Empty<string>();
    public string Summary { get; set; } = string.Empty;
    public string PivotSummary { get; set; } = string.Empty;
    public string RecommendedAction { get; set; } = string.Empty;
    public IReadOnlyList<string> SharedSignals { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> Domains { get; set; } = System.Array.Empty<string>();
}

public sealed class TyposquattingCandidateInfo
{
    public string Domain { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public int EditDistance { get; set; }
    public bool Resolves { get; set; }
    public bool AppearsRegistered { get; set; }
    public int RiskScore { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
    public string RiskSummary { get; set; } = string.Empty;
    public IReadOnlyList<string> RiskReasons { get; set; } = System.Array.Empty<string>();
    public string Disposition { get; set; } = string.Empty;
    public string DispositionSummary { get; set; } = string.Empty;
    public IReadOnlyList<string> DispositionReasons { get; set; } = System.Array.Empty<string>();
    public string InfrastructureClusterId { get; set; } = string.Empty;
    public string InfrastructureClusterLabel { get; set; } = string.Empty;
    public int InfrastructureClusterSize { get; set; }
    public string InfrastructureClusterSummary { get; set; } = string.Empty;
    public int ACount { get; set; }
    public int AaaaCount { get; set; }
    public int NsCount { get; set; }
    public int MxCount { get; set; }
    public string? Registrar { get; set; }
    public bool HttpReachable { get; set; }
    public int? HttpStatusCode { get; set; }
    public bool ThreatListed { get; set; }
    public string? ThreatSeverity { get; set; }
    public int TechnologyCount { get; set; }
    public int EnrichedIpCount { get; set; }
    public bool SmtpBannerReachable { get; set; }
    public bool SmtpRecipientAccepted { get; set; }
    public string PrimaryMxHost { get; set; } = string.Empty;
    public string SmtpBannerSummary { get; set; } = string.Empty;
    public string SmtpRecipientAcceptanceSummary { get; set; } = string.Empty;
    public bool LikelyOwned { get; set; }
    public int OwnershipConfidence { get; set; }
    public string OwnershipSummary { get; set; } = string.Empty;
    public IReadOnlyList<string> OwnershipSignals { get; set; } = System.Array.Empty<string>();
    public bool LikelyExternal { get; set; }
    public int ExternalConfidence { get; set; }
    public string ExternalSummary { get; set; } = string.Empty;
    public IReadOnlyList<string> ExternalSignals { get; set; } = System.Array.Empty<string>();
    public int ContentSimilarityScore { get; set; }
    public bool LikelyImpersonating { get; set; }
    public int? ContentFingerprintSimilarity { get; set; }
    public int? ContentFingerprintDistance { get; set; }
    public string ContentSimilaritySummary { get; set; } = string.Empty;
    public IReadOnlyList<string> ContentSimilaritySignals { get; set; } = System.Array.Empty<string>();
    public int VisualSimilarityScore { get; set; }
    public bool LikelyVisualClone { get; set; }
    public int? VisualSimilarityDistance { get; set; }
    public string VisualMatchKind { get; set; } = string.Empty;
    public string VisualMatchedSourceUrl { get; set; } = string.Empty;
    public string VisualCandidateArtifactUrl { get; set; } = string.Empty;
    public string VisualSimilaritySummary { get; set; } = string.Empty;
    public IReadOnlyList<string> VisualSimilaritySignals { get; set; } = System.Array.Empty<string>();
    public TyposquattingCandidateEnrichmentInfo? Enrichment { get; set; }
}

public sealed class TyposquattingCandidateEnrichmentInfo
{
    public WhoisInfo? Whois { get; set; }
    public HttpInfo? Http { get; set; }
    public ThreatIntelInfo? ThreatIntel { get; set; }
    public WebStaticScanInfo? WebStaticScan { get; set; }
    public IpEnrichmentInfo? IpEnrichment { get; set; }
    public string SmtpBannerSummary { get; set; } = string.Empty;
    public string SmtpRecipientAcceptanceSummary { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
}
