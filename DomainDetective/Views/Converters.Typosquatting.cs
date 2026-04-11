using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides typosquatting info functionality.</summary>
public sealed class TyposquattingInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the candidate count value.</summary>
    public int CandidateCount { get; set; }
    /// <summary>Gets or sets the active count value.</summary>
    public int ActiveCount { get; set; }
    /// <summary>Gets or sets the registered count value.</summary>
    public int RegisteredCount { get; set; }
    /// <summary>Gets or sets the contains homoglyphs value.</summary>
    public bool ContainsHomoglyphs { get; set; }
    /// <summary>Gets or sets the kind counts value.</summary>
    public IReadOnlyList<TyposquattingKindCount> KindCounts { get; set; } = System.Array.Empty<TyposquattingKindCount>();
    /// <summary>Gets or sets the candidates value.</summary>
    public IReadOnlyList<TyposquattingCandidateInfo> Candidates { get; set; } = System.Array.Empty<TyposquattingCandidateInfo>();
    /// <summary>Gets or sets the enriched candidate count value.</summary>
    public int EnrichedCandidateCount { get; set; }
    /// <summary>Gets or sets the reachable web count value.</summary>
    public int ReachableWebCount { get; set; }
    /// <summary>Gets or sets the threat listed count value.</summary>
    public int ThreatListedCount { get; set; }
    /// <summary>Gets or sets the high risk count value.</summary>
    public int HighRiskCount { get; set; }
    /// <summary>Gets or sets the likely owned count value.</summary>
    public int LikelyOwnedCount { get; set; }
    /// <summary>Gets or sets the likely external count value.</summary>
    public int LikelyExternalCount { get; set; }
    /// <summary>Gets or sets the ownership profile built value.</summary>
    public bool OwnershipProfileBuilt { get; set; }
    /// <summary>Gets or sets the likely impersonating count value.</summary>
    public int LikelyImpersonatingCount { get; set; }
    /// <summary>Gets or sets the content profile built value.</summary>
    public bool ContentProfileBuilt { get; set; }
    /// <summary>Gets or sets the likely visual clone count value.</summary>
    public int LikelyVisualCloneCount { get; set; }
    /// <summary>Gets or sets the visual profile built value.</summary>
    public bool VisualProfileBuilt { get; set; }
    /// <summary>Gets or sets the clustered candidate count value.</summary>
    public int ClusteredCandidateCount { get; set; }
    /// <summary>Gets or sets the infrastructure cluster count value.</summary>
    public int InfrastructureClusterCount { get; set; }
    /// <summary>Gets or sets the multi candidate infrastructure cluster count value.</summary>
    public int MultiCandidateInfrastructureClusterCount { get; set; }
    /// <summary>Gets or sets the largest infrastructure cluster size value.</summary>
    public int LargestInfrastructureClusterSize { get; set; }
    /// <summary>Gets or sets the campaigns value.</summary>
    public IReadOnlyList<TyposquattingCampaignInfo> Campaigns { get; set; } = System.Array.Empty<TyposquattingCampaignInfo>();
    /// <summary>Gets or sets the top response pack value.</summary>
    public TyposquattingResponsePackInfo? TopResponsePack { get; set; }
    /// <summary>Gets or sets the high priority campaign count value.</summary>
    public int HighPriorityCampaignCount { get; set; }
    /// <summary>Gets or sets the critical campaign count value.</summary>
    public int CriticalCampaignCount { get; set; }
    /// <summary>Gets or sets the available count value.</summary>
    public int AvailableCount { get; set; }
    /// <summary>Gets or sets the defensive owned disposition count value.</summary>
    public int DefensiveOwnedDispositionCount { get; set; }
    /// <summary>Gets or sets the monitor count value.</summary>
    public int MonitorCount { get; set; }
    /// <summary>Gets or sets the likely impersonation disposition count value.</summary>
    public int LikelyImpersonationDispositionCount { get; set; }
    /// <summary>Gets or sets the likely malicious count value.</summary>
    public int LikelyMaliciousCount { get; set; }
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public TyposquattingAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides typosquatting kind count functionality.</summary>
public sealed class TyposquattingKindCount
{
    /// <summary>Gets or sets the kind value.</summary>
    public string Kind { get; set; } = string.Empty;
    /// <summary>Gets or sets the count value.</summary>
    public int Count { get; set; }
}

/// <summary>Provides typosquatting response pack info functionality.</summary>
public sealed class TyposquattingResponsePackInfo
{
    /// <summary>Gets or sets the campaign value.</summary>
    public string Campaign { get; set; } = string.Empty;
    /// <summary>Gets or sets the severity value.</summary>
    public string Severity { get; set; } = string.Empty;
    /// <summary>Gets or sets the case id value.</summary>
    public string CaseId { get; set; } = string.Empty;
    /// <summary>Gets or sets the case fingerprint value.</summary>
    public string CaseFingerprint { get; set; } = string.Empty;
    /// <summary>Gets or sets the top domain value.</summary>
    public string TopDomain { get; set; } = string.Empty;
    /// <summary>Gets or sets the primary contact value.</summary>
    public string PrimaryContact { get; set; } = string.Empty;
    /// <summary>Gets or sets the tracking summary value.</summary>
    public string TrackingSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation summary value.</summary>
    public string EscalationSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the actionability summary value.</summary>
    public string ActionabilitySummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommended action value.</summary>
    public string RecommendedAction { get; set; } = string.Empty;
    /// <summary>Gets or sets the draft preview value.</summary>
    public string DraftPreview { get; set; } = string.Empty;
    /// <summary>Gets or sets the draft body value.</summary>
    public string DraftBody { get; set; } = string.Empty;
}

/// <summary>Provides typosquatting campaign info functionality.</summary>
public sealed class TyposquattingCampaignInfo
{
    /// <summary>Gets or sets the id value.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Gets or sets the label value.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>Gets or sets the severity value.</summary>
    public string Severity { get; set; } = string.Empty;
    /// <summary>Gets or sets the campaign score value.</summary>
    public int CampaignScore { get; set; }
    /// <summary>Gets or sets the candidate count value.</summary>
    public int CandidateCount { get; set; }
    /// <summary>Gets or sets the active count value.</summary>
    public int ActiveCount { get; set; }
    /// <summary>Gets or sets the reachable web count value.</summary>
    public int ReachableWebCount { get; set; }
    /// <summary>Gets or sets the threat listed count value.</summary>
    public int ThreatListedCount { get; set; }
    /// <summary>Gets or sets the likely malicious count value.</summary>
    public int LikelyMaliciousCount { get; set; }
    /// <summary>Gets or sets the likely impersonation count value.</summary>
    public int LikelyImpersonationCount { get; set; }
    /// <summary>Gets or sets the likely impersonating count value.</summary>
    public int LikelyImpersonatingCount { get; set; }
    /// <summary>Gets or sets the likely visual clone count value.</summary>
    public int LikelyVisualCloneCount { get; set; }
    /// <summary>Gets or sets the highest risk score value.</summary>
    public int HighestRiskScore { get; set; }
    /// <summary>Gets or sets the top candidate domain value.</summary>
    public string TopCandidateDomain { get; set; } = string.Empty;
    /// <summary>Gets or sets the top candidate disposition value.</summary>
    public string TopCandidateDisposition { get; set; } = string.Empty;
    /// <summary>Gets or sets the primary registrar value.</summary>
    public string PrimaryRegistrar { get; set; } = string.Empty;
    /// <summary>Gets or sets the registrar concentration percent value.</summary>
    public int RegistrarConcentrationPercent { get; set; }
    /// <summary>Gets or sets the primary hosting provider value.</summary>
    public string PrimaryHostingProvider { get; set; } = string.Empty;
    /// <summary>Gets or sets the hosting concentration percent value.</summary>
    public int HostingConcentrationPercent { get; set; }
    /// <summary>Gets or sets the primary country value.</summary>
    public string PrimaryCountry { get; set; } = string.Empty;
    /// <summary>Gets or sets the country concentration percent value.</summary>
    public int CountryConcentrationPercent { get; set; }
    /// <summary>Gets or sets the primary abuse contact value.</summary>
    public string PrimaryAbuseContact { get; set; } = string.Empty;
    /// <summary>Gets or sets the actionability score value.</summary>
    public int ActionabilityScore { get; set; }
    /// <summary>Gets or sets the actionability value.</summary>
    public string Actionability { get; set; } = string.Empty;
    /// <summary>Gets or sets the actionability summary value.</summary>
    public string ActionabilitySummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the abuse contacts value.</summary>
    public IReadOnlyList<string> AbuseContacts { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the registrar contacts value.</summary>
    public IReadOnlyList<string> RegistrarContacts { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the hosting providers value.</summary>
    public IReadOnlyList<string> HostingProviders { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the countries value.</summary>
    public IReadOnlyList<string> Countries { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the escalation subject value.</summary>
    public string EscalationSubject { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation case id value.</summary>
    public string EscalationCaseId { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation case fingerprint value.</summary>
    public string EscalationCaseFingerprint { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation tracking summary value.</summary>
    public string EscalationTrackingSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation summary value.</summary>
    public string EscalationSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation evidence summary value.</summary>
    public string EscalationEvidenceSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation draft preview value.</summary>
    public string EscalationDraftPreview { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation draft body value.</summary>
    public string EscalationDraftBody { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation primary route value.</summary>
    public string EscalationPrimaryRoute { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation primary contact value.</summary>
    public string EscalationPrimaryContact { get; set; } = string.Empty;
    /// <summary>Gets or sets the escalation contacts value.</summary>
    public IReadOnlyList<string> EscalationContacts { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the escalation domains value.</summary>
    public IReadOnlyList<string> EscalationDomains { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the escalation evidence points value.</summary>
    public IReadOnlyList<string> EscalationEvidencePoints { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the escalation checklist value.</summary>
    public IReadOnlyList<string> EscalationChecklist { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the pivot summary value.</summary>
    public string PivotSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommended action value.</summary>
    public string RecommendedAction { get; set; } = string.Empty;
    /// <summary>Gets or sets the shared signals value.</summary>
    public IReadOnlyList<string> SharedSignals { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the domains value.</summary>
    public IReadOnlyList<string> Domains { get; set; } = System.Array.Empty<string>();
}

/// <summary>Provides typosquatting candidate info functionality.</summary>
public sealed class TyposquattingCandidateInfo
{
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; set; } = string.Empty;
    /// <summary>Gets or sets the kind value.</summary>
    public string Kind { get; set; } = string.Empty;
    /// <summary>Gets or sets the edit distance value.</summary>
    public int EditDistance { get; set; }
    /// <summary>Gets or sets the resolves value.</summary>
    public bool Resolves { get; set; }
    /// <summary>Gets or sets the appears registered value.</summary>
    public bool AppearsRegistered { get; set; }
    /// <summary>Gets or sets the risk score value.</summary>
    public int RiskScore { get; set; }
    /// <summary>Gets or sets the risk level value.</summary>
    public string RiskLevel { get; set; } = string.Empty;
    /// <summary>Gets or sets the risk summary value.</summary>
    public string RiskSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the risk reasons value.</summary>
    public IReadOnlyList<string> RiskReasons { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the disposition value.</summary>
    public string Disposition { get; set; } = string.Empty;
    /// <summary>Gets or sets the disposition summary value.</summary>
    public string DispositionSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the disposition reasons value.</summary>
    public IReadOnlyList<string> DispositionReasons { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the infrastructure cluster id value.</summary>
    public string InfrastructureClusterId { get; set; } = string.Empty;
    /// <summary>Gets or sets the infrastructure cluster label value.</summary>
    public string InfrastructureClusterLabel { get; set; } = string.Empty;
    /// <summary>Gets or sets the infrastructure cluster size value.</summary>
    public int InfrastructureClusterSize { get; set; }
    /// <summary>Gets or sets the infrastructure cluster summary value.</summary>
    public string InfrastructureClusterSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the a count value.</summary>
    public int ACount { get; set; }
    /// <summary>Gets or sets the aaaa count value.</summary>
    public int AaaaCount { get; set; }
    /// <summary>Gets or sets the ns count value.</summary>
    public int NsCount { get; set; }
    /// <summary>Gets or sets the mx count value.</summary>
    public int MxCount { get; set; }
    /// <summary>Gets or sets the registrar value.</summary>
    public string? Registrar { get; set; }
    /// <summary>Gets or sets the http reachable value.</summary>
    public bool HttpReachable { get; set; }
    /// <summary>Gets or sets the http status code value.</summary>
    public int? HttpStatusCode { get; set; }
    /// <summary>Gets or sets the threat listed value.</summary>
    public bool ThreatListed { get; set; }
    /// <summary>Gets or sets the threat severity value.</summary>
    public string? ThreatSeverity { get; set; }
    /// <summary>Gets or sets the technology count value.</summary>
    public int TechnologyCount { get; set; }
    /// <summary>Gets or sets the enriched ip count value.</summary>
    public int EnrichedIpCount { get; set; }
    /// <summary>Gets or sets the smtp banner reachable value.</summary>
    public bool SmtpBannerReachable { get; set; }
    /// <summary>Gets or sets the smtp recipient accepted value.</summary>
    public bool SmtpRecipientAccepted { get; set; }
    /// <summary>Gets or sets the primary mx host value.</summary>
    public string PrimaryMxHost { get; set; } = string.Empty;
    /// <summary>Gets or sets the smtp banner summary value.</summary>
    public string SmtpBannerSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the smtp recipient acceptance summary value.</summary>
    public string SmtpRecipientAcceptanceSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the likely owned value.</summary>
    public bool LikelyOwned { get; set; }
    /// <summary>Gets or sets the ownership confidence value.</summary>
    public int OwnershipConfidence { get; set; }
    /// <summary>Gets or sets the ownership summary value.</summary>
    public string OwnershipSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the ownership signals value.</summary>
    public IReadOnlyList<string> OwnershipSignals { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the likely external value.</summary>
    public bool LikelyExternal { get; set; }
    /// <summary>Gets or sets the external confidence value.</summary>
    public int ExternalConfidence { get; set; }
    /// <summary>Gets or sets the external summary value.</summary>
    public string ExternalSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the external signals value.</summary>
    public IReadOnlyList<string> ExternalSignals { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the content similarity score value.</summary>
    public int ContentSimilarityScore { get; set; }
    /// <summary>Gets or sets the likely impersonating value.</summary>
    public bool LikelyImpersonating { get; set; }
    /// <summary>Gets or sets the content fingerprint similarity value.</summary>
    public int? ContentFingerprintSimilarity { get; set; }
    /// <summary>Gets or sets the content fingerprint distance value.</summary>
    public int? ContentFingerprintDistance { get; set; }
    /// <summary>Gets or sets the content similarity summary value.</summary>
    public string ContentSimilaritySummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the content similarity signals value.</summary>
    public IReadOnlyList<string> ContentSimilaritySignals { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the visual similarity score value.</summary>
    public int VisualSimilarityScore { get; set; }
    /// <summary>Gets or sets the likely visual clone value.</summary>
    public bool LikelyVisualClone { get; set; }
    /// <summary>Gets or sets the visual similarity distance value.</summary>
    public int? VisualSimilarityDistance { get; set; }
    /// <summary>Gets or sets the visual match kind value.</summary>
    public string VisualMatchKind { get; set; } = string.Empty;
    /// <summary>Gets or sets the visual matched source url value.</summary>
    public string VisualMatchedSourceUrl { get; set; } = string.Empty;
    /// <summary>Gets or sets the visual candidate artifact url value.</summary>
    public string VisualCandidateArtifactUrl { get; set; } = string.Empty;
    /// <summary>Gets or sets the visual similarity summary value.</summary>
    public string VisualSimilaritySummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the visual similarity signals value.</summary>
    public IReadOnlyList<string> VisualSimilaritySignals { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the enrichment value.</summary>
    public TyposquattingCandidateEnrichmentInfo? Enrichment { get; set; }
}

/// <summary>Provides typosquatting candidate enrichment info functionality.</summary>
public sealed class TyposquattingCandidateEnrichmentInfo
{
    /// <summary>Gets or sets the whois value.</summary>
    public WhoisInfo? Whois { get; set; }
    /// <summary>Gets or sets the http value.</summary>
    public HttpInfo? Http { get; set; }
    /// <summary>Gets or sets the threat intel value.</summary>
    public ThreatIntelInfo? ThreatIntel { get; set; }
    /// <summary>Gets or sets the web static scan value.</summary>
    public WebStaticScanInfo? WebStaticScan { get; set; }
    /// <summary>Gets or sets the ip enrichment value.</summary>
    public IpEnrichmentInfo? IpEnrichment { get; set; }
    /// <summary>Gets or sets the smtp banner summary value.</summary>
    public string SmtpBannerSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the smtp recipient acceptance summary value.</summary>
    public string SmtpRecipientAcceptanceSummary { get; set; } = string.Empty;
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
}
