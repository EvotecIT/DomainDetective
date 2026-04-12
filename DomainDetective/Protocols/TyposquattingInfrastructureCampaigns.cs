using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Analyst-facing severity for a shared typosquatting infrastructure campaign.
/// </summary>
public enum TyposquattingInfrastructureCampaignSeverity
{
    /// <summary>Defines values for typosquatting infrastructure campaign actionability.</summary>
    None,
    /// <summary>Defines values for typosquatting infrastructure campaign actionability.</summary>
    Low,
    /// <summary>Defines values for typosquatting infrastructure campaign actionability.</summary>
    Medium,
    /// <summary>Defines values for typosquatting infrastructure campaign actionability.</summary>
    High,
    /// <summary>Defines values for typosquatting infrastructure campaign actionability.</summary>
    Critical
}

/// <summary>
/// Analyst-facing response priority for acting on a shared typosquatting infrastructure campaign.
/// </summary>
public enum TyposquattingInfrastructureCampaignActionability
{
    /// <summary>Provides typosquatting infrastructure campaign functionality.</summary>
    None,
    /// <summary>Provides typosquatting infrastructure campaign functionality.</summary>
    Low,
    /// <summary>Provides typosquatting infrastructure campaign functionality.</summary>
    Medium,
    /// <summary>Provides typosquatting infrastructure campaign functionality.</summary>
    High,
    /// <summary>Provides typosquatting infrastructure campaign functionality.</summary>
    Immediate
}

/// <summary>
/// Rollup view of a suspicious infrastructure campaign spanning one or more lookalike domains.
/// </summary>
public sealed class TyposquattingInfrastructureCampaign
{
    /// <summary>Gets or sets the id value.</summary>
    public string Id { get; init; } = string.Empty;
    /// <summary>Gets or sets the label value.</summary>
    public string Label { get; init; } = string.Empty;
    /// <summary>Gets or sets the cluster id value.</summary>
    public string ClusterId { get; init; } = string.Empty;
    /// <summary>Gets or sets the campaign score value.</summary>
    public int CampaignScore { get; init; }
    /// <summary>Gets or sets the severity value.</summary>
    public TyposquattingInfrastructureCampaignSeverity Severity { get; init; }
    /// <summary>Gets or sets the candidate count value.</summary>
    public int CandidateCount { get; init; }
    /// <summary>Gets or sets the active count value.</summary>
    public int ActiveCount { get; init; }
    /// <summary>Gets or sets the reachable web count value.</summary>
    public int ReachableWebCount { get; init; }
    /// <summary>Gets or sets the threat listed count value.</summary>
    public int ThreatListedCount { get; init; }
    /// <summary>Gets or sets the likely malicious count value.</summary>
    public int LikelyMaliciousCount { get; init; }
    /// <summary>Gets or sets the likely impersonation count value.</summary>
    public int LikelyImpersonationCount { get; init; }
    /// <summary>Gets or sets the likely impersonating count value.</summary>
    public int LikelyImpersonatingCount { get; init; }
    /// <summary>Gets or sets the likely visual clone count value.</summary>
    public int LikelyVisualCloneCount { get; init; }
    /// <summary>Gets or sets the highest risk score value.</summary>
    public int HighestRiskScore { get; init; }
    /// <summary>Gets or sets the top candidate domain value.</summary>
    public string TopCandidateDomain { get; init; } = string.Empty;
    /// <summary>Gets or sets the top candidate disposition value.</summary>
    public string TopCandidateDisposition { get; init; } = string.Empty;
    /// <summary>Gets or sets the primary registrar value.</summary>
    public string PrimaryRegistrar { get; init; } = string.Empty;
    /// <summary>Gets or sets the registrar concentration percent value.</summary>
    public int RegistrarConcentrationPercent { get; init; }
    /// <summary>Gets or sets the primary hosting provider value.</summary>
    public string PrimaryHostingProvider { get; init; } = string.Empty;
    /// <summary>Gets or sets the hosting concentration percent value.</summary>
    public int HostingConcentrationPercent { get; init; }
    /// <summary>Gets or sets the primary country value.</summary>
    public string PrimaryCountry { get; init; } = string.Empty;
    /// <summary>Gets or sets the country concentration percent value.</summary>
    public int CountryConcentrationPercent { get; init; }
    /// <summary>Gets or sets the primary abuse contact value.</summary>
    public string PrimaryAbuseContact { get; init; } = string.Empty;
    /// <summary>Gets or sets the actionability score value.</summary>
    public int ActionabilityScore { get; init; }
    /// <summary>Gets or sets the actionability value.</summary>
    public TyposquattingInfrastructureCampaignActionability Actionability { get; init; }
    /// <summary>Gets or sets the actionability summary value.</summary>
    public string ActionabilitySummary { get; init; } = string.Empty;
    /// <summary>Gets or sets the abuse contacts value.</summary>
    public IReadOnlyList<string> AbuseContacts { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the registrar contacts value.</summary>
    public IReadOnlyList<string> RegistrarContacts { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the hosting providers value.</summary>
    public IReadOnlyList<string> HostingProviders { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the countries value.</summary>
    public IReadOnlyList<string> Countries { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the escalation bundle value.</summary>
    public TyposquattingInfrastructureCampaignEscalationBundle EscalationBundle { get; init; } = new();
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; init; } = string.Empty;
    /// <summary>Gets or sets the pivot summary value.</summary>
    public string PivotSummary { get; init; } = string.Empty;
    /// <summary>Gets or sets the recommended action value.</summary>
    public string RecommendedAction { get; init; } = string.Empty;
    /// <summary>Gets or sets the domains value.</summary>
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the shared signals value.</summary>
    public IReadOnlyList<string> SharedSignals { get; init; } = Array.Empty<string>();
    /// <summary>Represents the requires urgent review value.</summary>
    public bool RequiresUrgentReview => Severity == TyposquattingInfrastructureCampaignSeverity.High || Severity == TyposquattingInfrastructureCampaignSeverity.Critical;
}

/// <summary>
/// Builds campaign-level rollups from clustered typosquatting candidates.
/// </summary>
public static class TyposquattingInfrastructureCampaignAnalyzer
{
    /// <summary>Builds campaigns.</summary>
    public static IReadOnlyList<TyposquattingInfrastructureCampaign> BuildCampaigns(
        IReadOnlyList<TyposquattingInfrastructureCluster>? clusters,
        IReadOnlyList<TyposquattingCandidate>? candidates)
    {
        if (clusters == null || clusters.Count == 0 || candidates == null || candidates.Count == 0)
        {
            return Array.Empty<TyposquattingInfrastructureCampaign>();
        }

        var membersByCluster = candidates
            .Where(static candidate => candidate?.InfrastructureCluster != null)
            .GroupBy(static candidate => candidate.InfrastructureCluster!.Id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                static group => group.Key,
                static group => group
                    .OrderByDescending(static candidate => candidate.RiskScore)
                    .ThenBy(static candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                StringComparer.OrdinalIgnoreCase);

        var campaigns = new List<TyposquattingInfrastructureCampaign>();
        foreach (var cluster in clusters)
        {
            if (cluster == null || !membersByCluster.TryGetValue(cluster.Id, out var members) || members.Length == 0)
            {
                continue;
            }

            campaigns.Add(BuildCampaign(cluster, members));
        }

        return campaigns
            .OrderByDescending(static campaign => campaign.ActionabilityScore)
            .ThenByDescending(static campaign => campaign.CampaignScore)
            .ThenByDescending(static campaign => campaign.CandidateCount)
            .ThenByDescending(static campaign => campaign.HighestRiskScore)
            .ThenBy(static campaign => campaign.Label, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static TyposquattingInfrastructureCampaign BuildCampaign(
        TyposquattingInfrastructureCluster cluster,
        IReadOnlyList<TyposquattingCandidate> members)
    {
        var activeCount = members.Count(static candidate => candidate.Resolves);
        var reachableWebCount = members.Count(static candidate => candidate.Enrichment?.Http?.IsReachable == true);
        var threatListedCount = members.Count(static candidate => candidate.Enrichment?.ThreatIntel?.Listings?.Any(listing => listing.IsListed) == true);
        var likelyMaliciousCount = members.Count(static candidate => candidate.Disposition == TyposquattingDisposition.LikelyMalicious);
        var likelyImpersonationCount = members.Count(static candidate => candidate.Disposition == TyposquattingDisposition.LikelyImpersonation);
        var likelyImpersonatingCount = members.Count(static candidate => candidate.ContentSimilarity?.LikelyImpersonating == true);
        var likelyVisualCloneCount = members.Count(static candidate => candidate.VisualSimilarity?.LikelyClone == true);
        var registrars = BuildTopCounts(
            members.Select(static candidate => candidate.Enrichment?.Whois?.Registrar),
            5);
        var abuseContacts = BuildTopCounts(
            members.Select(static candidate => FirstNonEmpty(
                candidate.Enrichment?.Whois?.RegistrarAbuseEmail,
                candidate.Enrichment?.Whois?.RegistrarEmail,
                candidate.Enrichment?.Whois?.RegistrarWebsite)),
            5);
        var registrarContacts = BuildTopCounts(
            members.Select(static candidate => FirstNonEmpty(
                candidate.Enrichment?.Whois?.RegistrarEmail,
                candidate.Enrichment?.Whois?.RegistrarWebsite,
                candidate.Enrichment?.Whois?.RegistrarTel)),
            5);
        var hostingProviders = BuildTopCounts(
            members.SelectMany(static candidate => candidate.Enrichment?.IpEnrichment?.Rows?.Select(static row => row.AsName) ?? Array.Empty<string>()),
            5);
        var countries = BuildTopCounts(
            members.SelectMany(static candidate => candidate.Enrichment?.IpEnrichment?.Rows?.Select(static row => row.Country) ?? Array.Empty<string>()),
            5);
        var campaignScore = ComputeCampaignScore(
            cluster,
            members.Count,
            activeCount,
            reachableWebCount,
            threatListedCount,
            likelyMaliciousCount,
            likelyImpersonationCount,
            likelyImpersonatingCount,
            likelyVisualCloneCount);
        var severity = ClassifySeverity(
            campaignScore,
            activeCount,
            threatListedCount,
            likelyMaliciousCount,
            likelyImpersonationCount);
        var topCandidate = members[0];
        var primaryRegistrar = registrars.FirstOrDefault();
        var primaryHostingProvider = hostingProviders.FirstOrDefault();
        var primaryCountry = countries.FirstOrDefault();
        var primaryAbuseContact = abuseContacts.FirstOrDefault();
        var registrarConcentrationPercent = ComputeMemberConcentrationPercent(
            primaryRegistrar,
            members,
            static candidate => candidate.Enrichment?.Whois?.Registrar);
        var hostingConcentrationPercent = ComputeMemberConcentrationPercent(
            primaryHostingProvider,
            members,
            static candidate => candidate.Enrichment?.IpEnrichment?.Rows?.Select(static row => row.AsName) ?? Array.Empty<string>());
        var countryConcentrationPercent = ComputeMemberConcentrationPercent(
            primaryCountry,
            members,
            static candidate => candidate.Enrichment?.IpEnrichment?.Rows?.Select(static row => row.Country) ?? Array.Empty<string>());
        var pivotSummary = BuildPivotSummary(
            primaryRegistrar,
            registrarConcentrationPercent,
            primaryHostingProvider,
            hostingConcentrationPercent,
            primaryCountry,
            countryConcentrationPercent,
            primaryAbuseContact);
        var actionabilityScore = ComputeActionabilityScore(
            severity,
            members.Count,
            threatListedCount,
            likelyMaliciousCount,
            likelyImpersonationCount,
            likelyImpersonatingCount,
            likelyVisualCloneCount,
            primaryAbuseContact,
            primaryRegistrar,
            primaryHostingProvider,
            registrarConcentrationPercent,
            hostingConcentrationPercent);
        var actionability = ClassifyActionability(actionabilityScore);
        var actionabilitySummary = BuildActionabilitySummary(
            actionability,
            primaryAbuseContact,
            primaryRegistrar,
            primaryHostingProvider,
            registrarConcentrationPercent,
            hostingConcentrationPercent);
        var escalationBundle = TyposquattingInfrastructureCampaignEscalationBuilder.Build(
            cluster.Label,
            members,
            severity,
            actionability,
            abuseContacts,
            registrarContacts,
            hostingProviders,
            primaryAbuseContact,
            primaryRegistrar,
            primaryHostingProvider,
            primaryCountry,
            cluster.SharedSignals);

        return new TyposquattingInfrastructureCampaign
        {
            Id = "campaign-" + cluster.Id,
            Label = cluster.Label,
            ClusterId = cluster.Id,
            CampaignScore = campaignScore,
            Severity = severity,
            CandidateCount = members.Count,
            ActiveCount = activeCount,
            ReachableWebCount = reachableWebCount,
            ThreatListedCount = threatListedCount,
            LikelyMaliciousCount = likelyMaliciousCount,
            LikelyImpersonationCount = likelyImpersonationCount,
            LikelyImpersonatingCount = likelyImpersonatingCount,
            LikelyVisualCloneCount = likelyVisualCloneCount,
            HighestRiskScore = cluster.HighestRiskScore,
            TopCandidateDomain = topCandidate.Domain,
            TopCandidateDisposition = topCandidate.Disposition.ToString(),
            PrimaryRegistrar = primaryRegistrar ?? string.Empty,
            RegistrarConcentrationPercent = registrarConcentrationPercent,
            PrimaryHostingProvider = primaryHostingProvider ?? string.Empty,
            HostingConcentrationPercent = hostingConcentrationPercent,
            PrimaryCountry = primaryCountry ?? string.Empty,
            CountryConcentrationPercent = countryConcentrationPercent,
            PrimaryAbuseContact = primaryAbuseContact ?? string.Empty,
            ActionabilityScore = actionabilityScore,
            Actionability = actionability,
            ActionabilitySummary = actionabilitySummary,
            AbuseContacts = abuseContacts,
            RegistrarContacts = registrarContacts,
            HostingProviders = hostingProviders,
            Countries = countries,
            EscalationBundle = escalationBundle,
            Summary = BuildSummary(
                members.Count,
                activeCount,
                threatListedCount,
                likelyMaliciousCount,
                likelyImpersonationCount,
                likelyImpersonatingCount,
                likelyVisualCloneCount,
                cluster.SharedSignals),
            PivotSummary = pivotSummary,
            RecommendedAction = BuildRecommendedAction(severity, primaryAbuseContact, primaryRegistrar, primaryHostingProvider),
            Domains = cluster.Domains,
            SharedSignals = cluster.SharedSignals
        };
    }

    private static int ComputeCampaignScore(
        TyposquattingInfrastructureCluster cluster,
        int candidateCount,
        int activeCount,
        int reachableWebCount,
        int threatListedCount,
        int likelyMaliciousCount,
        int likelyImpersonationCount,
        int likelyImpersonatingCount,
        int likelyVisualCloneCount)
    {
        var score = cluster.HighestRiskScore;
        if (candidateCount > 1)
        {
            score += Math.Min(18, (candidateCount - 1) * 6);
        }

        score += Math.Min(18, activeCount * 9);
        score += Math.Min(10, reachableWebCount * 4);
        score += Math.Min(20, threatListedCount * 12);
        score += Math.Min(20, likelyMaliciousCount * 14);
        score += Math.Min(12, likelyImpersonationCount * 7);
        score += Math.Min(10, likelyImpersonatingCount * 5);
        score += Math.Min(10, likelyVisualCloneCount * 5);
        return Math.Max(0, Math.Min(100, score));
    }

    private static TyposquattingInfrastructureCampaignSeverity ClassifySeverity(
        int campaignScore,
        int activeCount,
        int threatListedCount,
        int likelyMaliciousCount,
        int likelyImpersonationCount)
    {
        if (likelyMaliciousCount > 0 && (threatListedCount > 0 || activeCount > 0))
        {
            return TyposquattingInfrastructureCampaignSeverity.Critical;
        }

        if (campaignScore >= 75 || (likelyImpersonationCount > 0 && activeCount > 0 && threatListedCount > 0))
        {
            return TyposquattingInfrastructureCampaignSeverity.High;
        }

        if (campaignScore >= 45)
        {
            return TyposquattingInfrastructureCampaignSeverity.Medium;
        }

        if (campaignScore > 0)
        {
            return TyposquattingInfrastructureCampaignSeverity.Low;
        }

        return TyposquattingInfrastructureCampaignSeverity.None;
    }

    private static int ComputeActionabilityScore(
        TyposquattingInfrastructureCampaignSeverity severity,
        int candidateCount,
        int threatListedCount,
        int likelyMaliciousCount,
        int likelyImpersonationCount,
        int likelyImpersonatingCount,
        int likelyVisualCloneCount,
        string? primaryAbuseContact,
        string? primaryRegistrar,
        string? primaryHostingProvider,
        int registrarConcentrationPercent,
        int hostingConcentrationPercent)
    {
        var score = severity switch
        {
            TyposquattingInfrastructureCampaignSeverity.Critical => 28,
            TyposquattingInfrastructureCampaignSeverity.High => 20,
            TyposquattingInfrastructureCampaignSeverity.Medium => 12,
            TyposquattingInfrastructureCampaignSeverity.Low => 6,
            _ => 0
        };

        if (!string.IsNullOrWhiteSpace(primaryAbuseContact))
        {
            score += 20;
        }

        if (!string.IsNullOrWhiteSpace(primaryRegistrar))
        {
            score += 10;
        }

        if (!string.IsNullOrWhiteSpace(primaryHostingProvider))
        {
            score += 8;
        }

        if (registrarConcentrationPercent >= 60)
        {
            score += 6;
        }

        if (hostingConcentrationPercent >= 60)
        {
            score += 6;
        }

        if (candidateCount > 1)
        {
            score += Math.Min(8, (candidateCount - 1) * 4);
        }

        if (threatListedCount > 0)
        {
            score += 8;
        }

        if (likelyMaliciousCount > 0)
        {
            score += 10;
        }

        if (likelyImpersonationCount > 0)
        {
            score += 6;
        }

        if (likelyImpersonatingCount > 0)
        {
            score += 4;
        }

        if (likelyVisualCloneCount > 0)
        {
            score += 4;
        }

        return Math.Max(0, Math.Min(100, score));
    }

    private static TyposquattingInfrastructureCampaignActionability ClassifyActionability(int score)
    {
        if (score >= 70)
        {
            return TyposquattingInfrastructureCampaignActionability.Immediate;
        }

        if (score >= 50)
        {
            return TyposquattingInfrastructureCampaignActionability.High;
        }

        if (score >= 25)
        {
            return TyposquattingInfrastructureCampaignActionability.Medium;
        }

        if (score > 0)
        {
            return TyposquattingInfrastructureCampaignActionability.Low;
        }

        return TyposquattingInfrastructureCampaignActionability.None;
    }

    private static string BuildSummary(
        int candidateCount,
        int activeCount,
        int threatListedCount,
        int likelyMaliciousCount,
        int likelyImpersonationCount,
        int likelyImpersonatingCount,
        int likelyVisualCloneCount,
        IReadOnlyList<string> sharedSignals)
    {
        var parts = new List<string>
        {
            candidateCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " domains"
        };

        if (likelyMaliciousCount > 0)
        {
            parts.Add(likelyMaliciousCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " likely malicious");
        }

        if (likelyImpersonationCount > 0)
        {
            parts.Add(likelyImpersonationCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " likely impersonation");
        }

        if (activeCount > 0)
        {
            parts.Add(activeCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " active");
        }

        if (threatListedCount > 0)
        {
            parts.Add(threatListedCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " threat-listed");
        }

        if (likelyImpersonatingCount > 0)
        {
            parts.Add(likelyImpersonatingCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " content lookalikes");
        }

        if (likelyVisualCloneCount > 0)
        {
            parts.Add(likelyVisualCloneCount.ToString(System.Globalization.CultureInfo.InvariantCulture) + " visual clones");
        }

        if (sharedSignals != null && sharedSignals.Count > 0)
        {
            parts.Add(string.Join(", ", sharedSignals));
        }

        return string.Join("; ", parts);
    }

    private static IReadOnlyList<string> BuildTopCounts(IEnumerable<string?> values, int take)
    {
        return values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!.Trim())
            .GroupBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Take(take)
            .Select(static group => group.Key)
            .ToArray();
    }

    private static int ComputeMemberConcentrationPercent(
        string? primary,
        IReadOnlyList<TyposquattingCandidate> members,
        Func<TyposquattingCandidate, string?> selector)
    {
        if (string.IsNullOrWhiteSpace(primary) || members == null || members.Count == 0)
        {
            return 0;
        }

        var normalizedPrimary = primary!.Trim();
        var matches = members.Count(candidate =>
        {
            var value = selector(candidate);
            return !string.IsNullOrWhiteSpace(value) && string.Equals(value!.Trim(), normalizedPrimary, StringComparison.OrdinalIgnoreCase);
        });
        if (matches <= 0)
        {
            return 0;
        }

        return (int)Math.Round(100d * matches / members.Count, MidpointRounding.AwayFromZero);
    }

    private static int ComputeMemberConcentrationPercent(
        string? primary,
        IReadOnlyList<TyposquattingCandidate> members,
        Func<TyposquattingCandidate, IEnumerable<string>> selector)
    {
        if (string.IsNullOrWhiteSpace(primary) || members == null || members.Count == 0)
        {
            return 0;
        }

        var normalizedPrimary = primary!.Trim();
        var matches = members.Count(candidate =>
            selector(candidate)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Any(value => string.Equals(value, normalizedPrimary, StringComparison.OrdinalIgnoreCase)));
        if (matches <= 0)
        {
            return 0;
        }

        return (int)Math.Round(100d * matches / members.Count, MidpointRounding.AwayFromZero);
    }

    private static string BuildPivotSummary(
        string? primaryRegistrar,
        int registrarConcentrationPercent,
        string? primaryHostingProvider,
        int hostingConcentrationPercent,
        string? primaryCountry,
        int countryConcentrationPercent,
        string? primaryAbuseContact)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(primaryRegistrar))
        {
            parts.Add("registrar " + primaryRegistrar + " (" + registrarConcentrationPercent.ToString(System.Globalization.CultureInfo.InvariantCulture) + "%)");
        }

        if (!string.IsNullOrWhiteSpace(primaryHostingProvider))
        {
            parts.Add("hosting " + primaryHostingProvider + " (" + hostingConcentrationPercent.ToString(System.Globalization.CultureInfo.InvariantCulture) + "%)");
        }

        if (!string.IsNullOrWhiteSpace(primaryCountry))
        {
            parts.Add("country " + primaryCountry + " (" + countryConcentrationPercent.ToString(System.Globalization.CultureInfo.InvariantCulture) + "%)");
        }

        if (!string.IsNullOrWhiteSpace(primaryAbuseContact))
        {
            parts.Add("abuse " + primaryAbuseContact);
        }

        return parts.Count > 0 ? string.Join("; ", parts) : "no registrar or hosting pivots detected";
    }

    private static string BuildActionabilitySummary(
        TyposquattingInfrastructureCampaignActionability actionability,
        string? primaryAbuseContact,
        string? primaryRegistrar,
        string? primaryHostingProvider,
        int registrarConcentrationPercent,
        int hostingConcentrationPercent)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(primaryAbuseContact))
        {
            parts.Add("abuse contact ready");
        }

        if (!string.IsNullOrWhiteSpace(primaryRegistrar) && registrarConcentrationPercent >= 60)
        {
            parts.Add("registrar concentrated");
        }

        if (!string.IsNullOrWhiteSpace(primaryHostingProvider) && hostingConcentrationPercent >= 60)
        {
            parts.Add("hosting concentrated");
        }

        if (parts.Count == 0)
        {
            parts.Add("limited direct takedown pivots");
        }

        return $"{actionability} priority: {string.Join(", ", parts)}";
    }

    private static string BuildRecommendedAction(
        TyposquattingInfrastructureCampaignSeverity severity,
        string? primaryAbuseContact,
        string? primaryRegistrar,
        string? primaryHostingProvider)
    {
        if (severity == TyposquattingInfrastructureCampaignSeverity.Critical || severity == TyposquattingInfrastructureCampaignSeverity.High)
        {
            if (!string.IsNullOrWhiteSpace(primaryAbuseContact))
            {
                return "Escalate immediately and prepare registrar or abuse notification via " + primaryAbuseContact;
            }

            if (!string.IsNullOrWhiteSpace(primaryRegistrar))
            {
                return "Escalate immediately and prepare registrar outreach to " + primaryRegistrar;
            }

            if (!string.IsNullOrWhiteSpace(primaryHostingProvider))
            {
                return "Escalate immediately and investigate takedown paths with " + primaryHostingProvider;
            }

            return "Escalate immediately and investigate takedown paths for the shared infrastructure";
        }

        if (!string.IsNullOrWhiteSpace(primaryRegistrar))
        {
            return "Monitor the campaign and retain registrar context for rapid takedown with " + primaryRegistrar;
        }

        return "Monitor the campaign and retain infrastructure pivots for rapid follow-up";
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value!.Trim();
            }
        }

        return null;
    }
}
