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
            foreach (var g in providerMatch.Gateways ?? new List<DomainDetective.Providers.Email.IMailProvider>())
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
        var gateways = providerMatch.Gateways?.Select(g => g.DisplayName).Distinct().ToList() ?? new List<string>();

        return new MxInfo
        {
            Check = HealthCheckType.MX,
            Area = AreaForKind(HealthCheckType.MX),
            Subject = analysis.Subject,
            MxRecords = analysis.MxRecords,
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
            ProviderPrimary = providerMatch.Primary?.DisplayName,
            ProviderPrimaryScore = providerMatch.PrimaryScore,
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

public class MxInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<string> MxRecords { get; set; }
    public bool MxRecordExists { get; set; }
    public bool PointsToCname { get; set; }
    public bool PointsToIpAddress { get; set; }
    public bool PointsToNonExistentDomain { get; set; }
    public bool PointsToDomainWithoutAOrAaaaRecord { get; set; }
    public bool PrioritiesInOrder { get; set; }
    public bool HasBackupServers { get; set; }
    public bool HasNullMx { get; set; }
    public bool PointsToLocalhost { get; set; }
    public bool Ipv6Supported { get; set; }
    public bool MxTtlUniform { get; set; }
    public bool MxRrsetConsistentAcrossNs { get; set; }
    public bool TargetAddressConsistentAcrossNs { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MXAnalysis Raw { get; set; }
    public string? ProviderPrimary { get; set; }
    public double ProviderPrimaryScore { get; set; }
    public IReadOnlyList<string> ProviderGateways { get; set; }
    public IReadOnlyList<ProviderHelpLinks> ProviderHelp { get; set; }
}

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
