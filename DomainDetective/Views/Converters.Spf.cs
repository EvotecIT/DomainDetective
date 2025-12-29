using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SpfRecordInfo Convert(SpfAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        // Narrative (business-friendly text blocks)
        var narrative = DomainDetective.Narratives.SpfNarrative.Build(analysis);
        // Build provider summary from part analyses
        var providerCounts = new Dictionary<string, int>(System.StringComparer.OrdinalIgnoreCase);
        if (analysis.SpfPartAnalyses != null)
        {
            foreach (var p in analysis.SpfPartAnalyses)
            {
                if (!string.IsNullOrWhiteSpace(p.Provider))
                {
                    providerCounts[p.Provider!] = providerCounts.TryGetValue(p.Provider!, out var c) ? c + 1 : 1;
                }
            }
        }
        var allMechanism = analysis.AllMechanism;
        var policy = string.IsNullOrWhiteSpace(allMechanism) ? "none" : allMechanism!.ToLowerInvariant();
        // Provider help (from SPF tokens)
        var spfTokens = new List<string>();
        try
        {
            if (analysis.IncludeRecords != null) spfTokens.AddRange(analysis.IncludeRecords);
            if (analysis.ResolvedIncludeRecords != null) spfTokens.AddRange(analysis.ResolvedIncludeRecords);
            if (!string.IsNullOrWhiteSpace(analysis.SpfRecord)) spfTokens.Add(analysis.SpfRecord);
        }
        catch { }
        var match = DomainDetective.Providers.Email.EmailProviderDetector.Detect(mxHosts: Array.Empty<string>(), spfTokens: spfTokens, dkimTargets: Array.Empty<string>());
        var helpList = new List<ProviderHelpLinks>();
        try
        {
            if (match?.Primary != null)
            {
                var p = match.Primary;
                var ph = new ProviderHelpLinks
                {
                    ProviderName = p.DisplayName,
                    Dmarc = p.Docs?.Dmarc?.Url,
                    Spf = p.Docs?.Spf?.Url,
                    Dkim = p.Docs?.Dkim?.Url,
                    MtaSts = p.Docs?.MtaSts?.Url,
                    TlsRpt = p.Docs?.TlsRpt?.Url,
                    Deliverability = p.Docs?.Deliverability?.Url,
                    Topics = Converters_MakeTopics(p.DisplayName, p.Docs, new []
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
                if (ph.HasAny) helpList.Add(ph);
            }
            foreach (var o in (match?.OutboundSenders ?? new List<DomainDetective.Providers.Email.IMailProvider>()))
            {
                var ph = new ProviderHelpLinks
                {
                    ProviderName = o.DisplayName,
                    Dmarc = o.Docs?.Dmarc?.Url,
                    Spf = o.Docs?.Spf?.Url,
                    Dkim = o.Docs?.Dkim?.Url,
                    MtaSts = o.Docs?.MtaSts?.Url,
                    TlsRpt = o.Docs?.TlsRpt?.Url,
                    Deliverability = o.Docs?.Deliverability?.Url,
                    Topics = Converters_MakeTopics(o.DisplayName, o.Docs, new []
                    {
                        ("DMARC", o.Docs?.Dmarc?.Url),
                        ("SPF", o.Docs?.Spf?.Url),
                        ("DKIM", o.Docs?.Dkim?.Url),
                        ("ARC", o.Docs?.Arc?.Url),
                        ("BIMI", o.Docs?.Bimi?.Url),
                        ("MTA-STS", o.Docs?.MtaSts?.Url),
                        ("TLS-RPT", o.Docs?.TlsRpt?.Url),
                        ("Deliverability", o.Docs?.Deliverability?.Url)
                    })
                };
                if (ph.HasAny) helpList.Add(ph);
            }
        }
        catch { }

        return new SpfRecordInfo
        {
            Check = HealthCheckType.SPF,
            Area = AreaForKind(HealthCheckType.SPF),
            Subject = analysis.Subject ?? string.Empty,
            SpfRecord = analysis.SpfRecord,
            DnsRecordTtl = analysis.DnsRecordTtl,
            CnameTtl = analysis.CnameTtl,
            IsCnameResolved = analysis.IsCnameResolved,
            RecordLength = analysis.SpfRecord?.Length ?? 0,
            SpfRecordExists = analysis.SpfRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            MultipleSpfRecords = analysis.MultipleSpfRecords,
            DnsLookupsCount = analysis.DnsLookupsCount,
            ExceedsDnsLookups = analysis.ExceedsDnsLookups,
            MultipleAllMechanisms = analysis.MultipleAllMechanisms,
            ExceedsTotalCharacterLimit = analysis.ExceedsTotalCharacterLimit,
            ExceedsCharacterLimit = analysis.ExceedsCharacterLimit,
            UnknownMechanisms = analysis.UnknownMechanisms,
            Mechanisms = analysis.SpfPartAnalyses ?? new List<SpfPartAnalysis>(),
            ProviderCounts = providerCounts,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"policy {policy}; lookups {analysis.DnsLookupsCount}/10; size {(analysis.ExceedsTotalCharacterLimit || analysis.ExceedsCharacterLimit ? "limit" : "ok")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis,
            Narrative = narrative,
            Highlights = narrative.Highlights,
            ProviderHelp = helpList
        };
    }

    private static List<ProviderHelpTopic> Converters_MakeTopics(string providerName, DomainDetective.Providers.Email.ProviderDocumentation? docs, IEnumerable<(string Topic, string? Url)> pairs)
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

public class SpfRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string SpfRecord { get; set; } = string.Empty;
    /// <summary>DNS TTL (seconds) of the SPF TXT record.</summary>
    public int? DnsRecordTtl { get; set; }
    /// <summary>TTL (seconds) of the CNAME record when resolved via CNAME alias.</summary>
    public int? CnameTtl { get; set; }
    /// <summary>True when the SPF record was resolved through a CNAME alias.</summary>
    public bool IsCnameResolved { get; set; }
    public int RecordLength { get; set; }
    public bool SpfRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool MultipleSpfRecords { get; set; }
    public int DnsLookupsCount { get; set; }
    public bool ExceedsDnsLookups { get; set; }
    public bool MultipleAllMechanisms { get; set; }
    public bool ExceedsTotalCharacterLimit { get; set; }
    public bool ExceedsCharacterLimit { get; set; }
    public IReadOnlyList<string> UnknownMechanisms { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<SpfPartAnalysis> Mechanisms { get; set; } = System.Array.Empty<SpfPartAnalysis>();
    public IReadOnlyDictionary<string, int> ProviderCounts { get; set; } = new System.Collections.Generic.Dictionary<string, int>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public SpfAnalysis Raw { get; set; } = new SpfAnalysis();
    public DomainDetective.Narratives.SpfNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.SpfNarrative.Sections();
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<ProviderHelpLinks> ProviderHelp { get; set; } = System.Array.Empty<ProviderHelpLinks>();
}
