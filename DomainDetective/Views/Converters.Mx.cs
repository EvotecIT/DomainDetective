using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MxInfo Convert(MXAnalysis analysis)
    {
        // MXAnalysis doesn't emit assessments yet; summarize will return OK/0/0
        Summarize(analysis is IHasAssessments has ? has.Assessments : new List<Assessment>(), out var warnCount, out var errCount, out var status);
        var recs = analysis is IHasAssessments h2 ? RecommendationEngine.FromProblems(h2.Assessments) : new List<RecommendationAdvice>();
        var positives = analysis is IHasAssessments h3 ? RecommendationEngine.FromPositives(h3.Assessments) : new List<RecommendationAdvice>();
        // Best-effort provider inference from MX only
        var hosts = new List<string>();
        try
        {
            foreach (var rr in analysis.MxRecords ?? new List<string>())
            {
                var parts = rr?.Split(new[] { ' ', '\t' }, 2, System.StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
                var host = parts.Length == 2 ? parts[1] : parts.FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(host)) hosts.Add(host.Trim('.'));
            }
        }
        catch { }
        var providerMatch = DomainDetective.Providers.Email.EmailProviderDetector.Detect(hosts);
        var providerHelps = new List<ProviderHelpLinks>();
        try
        {
            if (providerMatch?.Primary != null)
            {
                var p = providerMatch.Primary;
                var ph = new ProviderHelpLinks
                {
                    ProviderName = p.DisplayName,
                    Dmarc = p.Docs?.Dmarc?.Url,
                    Spf = p.Docs?.Spf?.Url,
                    Dkim = p.Docs?.Dkim?.Url,
                    MtaSts = p.Docs?.MtaSts?.Url,
                    TlsRpt = p.Docs?.TlsRpt?.Url,
                    Deliverability = p.Docs?.Deliverability?.Url,
                    Topics = BuildHelpTopics(p.DisplayName, p.Docs, new []
                    {
                        ("DMARC", p.Docs?.Dmarc?.Url),
                        ("SPF", p.Docs?.Spf?.Url),
                        ("DKIM", p.Docs?.Dkim?.Url),
                        ("ARC", p.Docs?.Arc?.Url),
                        ("BIMI", p.Docs?.Bimi?.Url),
                        ("MTA-STS", p.Docs?.MtaSts?.Url),
                        ("TLS-RPT", p.Docs?.TlsRpt?.Url),
                        ("Deliverability", p.Docs?.Deliverability?.Url)
                    })
                };
                if (ph.HasAny)
                {
                    providerHelps.Add(ph);
                }
            }
            // Gateways may have useful docs too
            foreach (var g in providerMatch?.Gateways ?? new List<DomainDetective.Providers.Email.IMailProvider>())
            {
                var gh = new ProviderHelpLinks
                {
                    ProviderName = g.DisplayName,
                    Dmarc = g.Docs?.Dmarc?.Url,
                    Spf = g.Docs?.Spf?.Url,
                    Dkim = g.Docs?.Dkim?.Url,
                    MtaSts = g.Docs?.MtaSts?.Url,
                    TlsRpt = g.Docs?.TlsRpt?.Url,
                    Deliverability = g.Docs?.Deliverability?.Url,
                    Topics = BuildHelpTopics(g.DisplayName, g.Docs, new []
                    {
                        ("DMARC", g.Docs?.Dmarc?.Url),
                        ("SPF", g.Docs?.Spf?.Url),
                        ("DKIM", g.Docs?.Dkim?.Url),
                        ("ARC", g.Docs?.Arc?.Url),
                        ("BIMI", g.Docs?.Bimi?.Url),
                        ("MTA-STS", g.Docs?.MtaSts?.Url),
                        ("TLS-RPT", g.Docs?.TlsRpt?.Url),
                        ("Deliverability", g.Docs?.Deliverability?.Url)
                    })
                };
                if (gh.HasAny)
                {
                    providerHelps.Add(gh);
                }
            }
        }
        catch { }
        var gateways = providerMatch?.Gateways?.Select(g => g.DisplayName).Distinct().ToList() ?? new List<string>();

        return new MxInfo
        {
            Check = HealthCheckType.MX,
            Area = AreaForKind(HealthCheckType.MX),
            Subject = analysis.Subject ?? string.Empty,
            MxRecords = analysis.MxRecords ?? new List<string>(),
            MxRecordTtls = analysis.MxRecordTtls,
            MinMxTtl = analysis.MinMxTtl,
            MaxMxTtl = analysis.MaxMxTtl,
            AvgMxTtl = analysis.AvgMxTtl,
            MxRecordExists = analysis.MxRecordExists,
            PointsToCname = analysis.PointsToCname,
            PointsToIpAddress = analysis.PointsToIpAddress,
            PointsToNonExistentDomain = analysis.PointsToNonExistentDomain,
            PointsToDomainWithoutAOrAaaaRecord = analysis.PointsToDomainWithoutAOrAaaaRecord,
            PrioritiesInOrder = analysis.PrioritiesInOrder,
            HasBackupServers = analysis.HasBackupServers,
            HasNullMx = analysis.HasNullMx,
            PointsToLocalhost = analysis.PointsToLocalhost,
            Ipv6Supported = analysis.Ipv6Supported,
            MxTtlUniform = analysis.MxTtlUniform,
            MxRrsetConsistentAcrossNs = analysis.MxRrsetConsistentAcrossNs,
            TargetAddressConsistentAcrossNs = analysis.TargetAddressConsistentAcrossNs,
            Assessments = analysis is IHasAssessments h ? h.Assessments : new List<Assessment>(),
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{analysis.MxRecords?.Count ?? 0} MX; backup {(analysis.HasBackupServers ? "yes" : "no")}\u002c TTL {(analysis.MxTtlUniform ? "uniform" : "mixed")}\u002c NS {(analysis.MxRrsetConsistentAcrossNs ? "consistent" : "differs")}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Raw = analysis,
            ProviderPrimary = providerMatch?.Primary?.DisplayName,
            ProviderPrimaryScore = providerMatch?.PrimaryScore ?? 0.0,
            ProviderGateways = gateways,
            ProviderHelp = providerHelps
        };
    }

    private static List<ProviderHelpTopic> BuildHelpTopics(string providerName, DomainDetective.Providers.Email.ProviderDocumentation? docs, IEnumerable<(string Topic, string? Url)> pairs)
    {
        var list = new List<ProviderHelpTopic>();
        foreach (var (topic, url) in pairs)
        {
            var meta = docs?.Get(topic);
            var effectiveUrl = string.IsNullOrWhiteSpace(url) ? meta?.Url : url;
            if (string.IsNullOrWhiteSpace(effectiveUrl)) continue;
            list.Add(new ProviderHelpTopic
            {
                Topic = topic,
                Url = effectiveUrl,
                Title = meta?.Title ?? ($"{providerName} — {topic}"),
                Summary = meta?.Summary,
                Notes = meta?.Notes,
                IsPublic = meta?.IsPublic ?? true,
                IsThirdParty = meta?.IsThirdParty ?? false,
                LastVerified = meta?.LastVerified
            });
        }
        return list;
    }
}

/// <summary>
/// View model summarizing MX (Mail Exchanger) analysis.
/// </summary>
public class MxInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>MX resource records as returned by DNS.</summary>
    public IReadOnlyList<string> MxRecords { get; set; } = System.Array.Empty<string>();
    /// <summary>TTL values (seconds) for MX answers as returned by DNS.</summary>
    public IReadOnlyList<int> MxRecordTtls { get; set; } = System.Array.Empty<int>();
    /// <summary>Minimum TTL (seconds) across MX answers (ignores 0).</summary>
    public int? MinMxTtl { get; set; }
    /// <summary>Maximum TTL (seconds) across MX answers (ignores 0).</summary>
    public int? MaxMxTtl { get; set; }
    /// <summary>Average TTL (seconds) across MX answers (ignores 0).</summary>
    public double? AvgMxTtl { get; set; }
    /// <summary>True when at least one MX record exists.</summary>
    public bool MxRecordExists { get; set; }
    /// <summary>True when MX points to a CNAME (discouraged).</summary>
    public bool PointsToCname { get; set; }
    /// <summary>True when MX points directly to an IP address (invalid).</summary>
    public bool PointsToIpAddress { get; set; }
    /// <summary>True when MX target does not exist.</summary>
    public bool PointsToNonExistentDomain { get; set; }
    /// <summary>True when MX target lacks A/AAAA records.</summary>
    public bool PointsToDomainWithoutAOrAaaaRecord { get; set; }
    /// <summary>True when MX preference values are in ascending order.</summary>
    public bool PrioritiesInOrder { get; set; }
    /// <summary>True when multiple MX preferences provide redundancy.</summary>
    public bool HasBackupServers { get; set; }
    /// <summary>True when NULL MX pattern is used.</summary>
    public bool HasNullMx { get; set; }
    /// <summary>True when any MX target is localhost.</summary>
    public bool PointsToLocalhost { get; set; }
    /// <summary>True when at least one MX target supports IPv6.</summary>
    public bool Ipv6Supported { get; set; }
    /// <summary>True when MX TTL values are uniform across the RRset.</summary>
    public bool MxTtlUniform { get; set; }
    /// <summary>True when MX RRsets are consistent across authoritative NS.</summary>
    public bool MxRrsetConsistentAcrossNs { get; set; }
    /// <summary>True when target A/AAAA answers are consistent across authoritative NS.</summary>
    public bool TargetAddressConsistentAcrossNs { get; set; }
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    /// <summary>Short summary text used in executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying MX analysis.</summary>
    public MXAnalysis Raw { get; set; } = new MXAnalysis();
    /// <summary>Primary provider inferred from MX (best-effort).</summary>
    public string? ProviderPrimary { get; set; }
    /// <summary>Confidence score for primary provider (0..1).</summary>
    public double ProviderPrimaryScore { get; set; }
    /// <summary>Gateway providers inferred from MX.</summary>
    public IReadOnlyList<string> ProviderGateways { get; set; } = System.Array.Empty<string>();
    /// <summary>Helpful vendor documentation links for this provider.</summary>
    public IReadOnlyList<ProviderHelpLinks> ProviderHelp { get; set; } = System.Array.Empty<ProviderHelpLinks>();
}

/// <summary>
/// Helpful vendor documentation links discovered for the current provider.
/// </summary>
public sealed class ProviderHelpLinks
{
    public string ProviderName { get; set; } = string.Empty;
    public string? Dmarc { get; set; }
    public string? Spf { get; set; }
    public string? Dkim { get; set; }
    public string? MtaSts { get; set; }
    public string? TlsRpt { get; set; }
    public string? Deliverability { get; set; }
    public List<ProviderHelpTopic> Topics { get; set; } = new();
    public bool HasAny => Topics?.Any(t => !string.IsNullOrWhiteSpace(t?.Url)) == true ||
                          !string.IsNullOrWhiteSpace(Dmarc) || !string.IsNullOrWhiteSpace(Spf) || !string.IsNullOrWhiteSpace(Dkim) || !string.IsNullOrWhiteSpace(MtaSts) || !string.IsNullOrWhiteSpace(TlsRpt) || !string.IsNullOrWhiteSpace(Deliverability);
}
