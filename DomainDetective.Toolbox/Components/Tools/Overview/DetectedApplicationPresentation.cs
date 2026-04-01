using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class DetectedApplicationPresentation
{
    public static IReadOnlyList<DetectedApplicationCategoryView> BuildCategories(IReadOnlyList<DetectedDnsApplication>? applications)
    {
        if (applications == null || applications.Count == 0)
        {
            return Array.Empty<DetectedApplicationCategoryView>();
        }

        return applications
            .GroupBy(static application => application.Category)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => GetCategoryLabel(group.Key), StringComparer.OrdinalIgnoreCase)
            .Select(static group => new DetectedApplicationCategoryView
            {
                CategoryLabel = GetCategoryLabel(group.Key),
                ApplicationCount = group.Count(),
                Applications = group
                    .GroupBy(static application => application.Name, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(static appGroup => appGroup.Max(static application => (int)application.Confidence))
                    .ThenBy(static appGroup => appGroup.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(BuildApplication)
                    .ToArray()
            })
            .ToArray();
    }

    private static DetectedApplicationItemView BuildApplication(IGrouping<string, DetectedDnsApplication> applicationGroup)
    {
        var ordered = applicationGroup
            .OrderByDescending(static application => (int)application.Confidence)
            .ThenBy(static application => application.EvidenceKind)
            .ToArray();

        var strongest = ordered[0];
        var evidenceKinds = ordered
            .Select(static application => GetEvidenceKindLabel(application.EvidenceKind))
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var sources = ordered
            .Select(static application => application.Source)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(3)
            .ToArray();

        var samples = ordered
            .Select(static application => GetEvidenceSample(application))
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(4)
            .ToArray();

        var confidence = strongest.Confidence == Microsoft365DetectionConfidence.Unknown
            ? "Observed"
            : strongest.Confidence.ToString();

        return new DetectedApplicationItemView
        {
            Name = strongest.Name,
            ConfidenceLabel = confidence,
            ObservationCount = ordered.Length,
            SourceLabel = sources.Length == 0 ? string.Empty : "Observed on " + string.Join(", ", sources),
            Summary = BuildSummary(strongest, evidenceKinds, ordered.Length),
            Signals = evidenceKinds,
            Samples = samples
        };
    }

    private static string BuildSummary(DetectedDnsApplication application, IReadOnlyList<string> evidenceKinds, int observationCount)
    {
        var signalSummary = evidenceKinds.Count == 0
            ? "Public DNS evidence"
            : string.Join(", ", evidenceKinds);
        var observationLabel = observationCount == 1 ? "1 observation" : observationCount + " observations";
        return $"{signalSummary} matched {application.Name} across {observationLabel}.";
    }

    private static string GetEvidenceSample(DetectedDnsApplication application)
    {
        var evidenceKind = GetEvidenceKindLabel(application.EvidenceKind);
        if (!string.IsNullOrWhiteSpace(application.Evidence))
        {
            return evidenceKind + ": " + Truncate(application.Evidence.Trim(), 88);
        }

        if (!string.IsNullOrWhiteSpace(application.Source))
        {
            return evidenceKind + " source: " + application.Source.Trim();
        }

        return evidenceKind;
    }

    private static string GetEvidenceKindLabel(DetectedDnsAppEvidenceKind evidenceKind)
    {
        return evidenceKind switch
        {
            DetectedDnsAppEvidenceKind.TxtRecord => "TXT",
            DetectedDnsAppEvidenceKind.MxRecord => "MX",
            DetectedDnsAppEvidenceKind.NsRecord => "NS",
            DetectedDnsAppEvidenceKind.CnameRecord => "CNAME",
            DetectedDnsAppEvidenceKind.Subdomain => "Subdomain",
            _ => "DNS"
        };
    }

    private static string GetCategoryLabel(DetectedDnsAppCategory category)
    {
        return category switch
        {
            DetectedDnsAppCategory.DmarcReporting => "DMARC Reporting",
            DetectedDnsAppCategory.DnsHosting => "DNS Hosting",
            DetectedDnsAppCategory.EmailMarketing => "Email Marketing",
            DetectedDnsAppCategory.EmailSecurity => "Email Security",
            DetectedDnsAppCategory.EmailSignatures => "Email Signatures",
            _ => category.ToString()
        };
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value.Substring(0, maxLength - 1) + "…";
    }
}

internal sealed class DetectedApplicationCategoryView
{
    public string CategoryLabel { get; init; } = string.Empty;
    public int ApplicationCount { get; init; }
    public IReadOnlyList<DetectedApplicationItemView> Applications { get; init; } = Array.Empty<DetectedApplicationItemView>();
}

internal sealed class DetectedApplicationItemView
{
    public string Name { get; init; } = string.Empty;
    public string ConfidenceLabel { get; init; } = string.Empty;
    public int ObservationCount { get; init; }
    public string SourceLabel { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Signals { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
}
