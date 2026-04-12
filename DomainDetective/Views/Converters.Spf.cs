using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
            ContainsCharactersAfterAll = analysis.ContainsCharactersAfterAll,
            HasPtrType = analysis.HasPtrType,
            HasNullLookups = analysis.HasNullLookups,
            HasRedirect = analysis.HasRedirect,
            HasExp = analysis.HasExp,
            InvalidIpSyntax = analysis.InvalidIpSyntax,
            DenyAll = analysis.DenyAll,
            AllMechanism = analysis.AllMechanism,
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
            Details = narrative.Details,
            Includes = analysis.IncludeRecords ?? new List<string>(),
            RedirectValue = analysis.RedirectValue,
            ExpValue = analysis.ExpValue,
            ResolvedIpv4Records = analysis.ResolvedIpv4Records ?? new List<string>(),
            ResolvedIpv6Records = analysis.ResolvedIpv6Records ?? new List<string>(),
            ResolvedIncludeRecords = analysis.ResolvedIncludeRecords ?? new List<string>(),
            FlattenedUniqueIps = analysis.FlattenedIpAnalysis?.UniqueIps ?? new List<string>(),
            FlattenedDuplicateIps = analysis.FlattenedIpAnalysis?.DuplicateIps ?? new List<string>(),
            EffectiveSpfSends = analysis.EffectiveSpfSends,
            PermError = analysis.PermError,
            Advisory = analysis.Advisory,
            CycleDetected = analysis.CycleDetected,
            CyclePath = analysis.CyclePath,
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

/// <summary>Provides spf record info functionality.</summary>
public class SpfRecordInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Gets or sets the spf record value.</summary>
    public string SpfRecord { get; set; } = string.Empty;
    /// <summary>DNS TTL (seconds) of the SPF TXT record.</summary>
    public int? DnsRecordTtl { get; set; }
    /// <summary>TTL (seconds) of the CNAME record when resolved via CNAME alias.</summary>
    public int? CnameTtl { get; set; }
    /// <summary>True when the SPF record was resolved through a CNAME alias.</summary>
    public bool IsCnameResolved { get; set; }
    /// <summary>Gets or sets the record length value.</summary>
    public int RecordLength { get; set; }
    /// <summary>Gets or sets the spf record exists value.</summary>
    public bool SpfRecordExists { get; set; }
    /// <summary>Gets or sets the starts correctly value.</summary>
    public bool StartsCorrectly { get; set; }
    /// <summary>Gets or sets the multiple spf records value.</summary>
    public bool MultipleSpfRecords { get; set; }
    /// <summary>Gets or sets the dns lookups count value.</summary>
    public int DnsLookupsCount { get; set; }
    /// <summary>Gets or sets the exceeds dns lookups value.</summary>
    public bool ExceedsDnsLookups { get; set; }
    /// <summary>Gets or sets the multiple all mechanisms value.</summary>
    public bool MultipleAllMechanisms { get; set; }
    /// <summary>Gets or sets the contains characters after all value.</summary>
    public bool ContainsCharactersAfterAll { get; set; }
    /// <summary>Gets or sets the has ptr type value.</summary>
    public bool HasPtrType { get; set; }
    /// <summary>Gets or sets the has null lookups value.</summary>
    public bool HasNullLookups { get; set; }
    /// <summary>Gets or sets the has redirect value.</summary>
    public bool HasRedirect { get; set; }
    /// <summary>Gets or sets the has exp value.</summary>
    public bool HasExp { get; set; }
    /// <summary>Gets or sets the invalid ip syntax value.</summary>
    public bool InvalidIpSyntax { get; set; }
    /// <summary>Gets or sets the deny all value.</summary>
    public bool DenyAll { get; set; }
    /// <summary>Gets or sets the all mechanism value.</summary>
    public string? AllMechanism { get; set; }
    /// <summary>Gets or sets the exceeds total character limit value.</summary>
    public bool ExceedsTotalCharacterLimit { get; set; }
    /// <summary>Gets or sets the exceeds character limit value.</summary>
    public bool ExceedsCharacterLimit { get; set; }
    /// <summary>Gets or sets the unknown mechanisms value.</summary>
    public IReadOnlyList<string> UnknownMechanisms { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the mechanisms value.</summary>
    public IReadOnlyList<SpfPartAnalysis> Mechanisms { get; set; } = System.Array.Empty<SpfPartAnalysis>();
    /// <summary>Gets or sets the provider counts value.</summary>
    public IReadOnlyDictionary<string, int> ProviderCounts { get; set; } = new System.Collections.Generic.Dictionary<string, int>();
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
    public SpfAnalysis Raw { get; set; } = new SpfAnalysis();
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.SpfNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.SpfNarrative.Sections();
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the details value.</summary>
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the includes value.</summary>
    public IReadOnlyList<string> Includes { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the redirect value value.</summary>
    public string? RedirectValue { get; set; }
    /// <summary>Gets or sets the exp value value.</summary>
    public string? ExpValue { get; set; }
    /// <summary>Gets or sets the resolved ipv4 records value.</summary>
    public IReadOnlyList<string> ResolvedIpv4Records { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the resolved ipv6 records value.</summary>
    public IReadOnlyList<string> ResolvedIpv6Records { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the resolved include records value.</summary>
    public IReadOnlyList<string> ResolvedIncludeRecords { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the flattened unique ips value.</summary>
    public IReadOnlyList<string> FlattenedUniqueIps { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the flattened duplicate ips value.</summary>
    public IReadOnlyList<string> FlattenedDuplicateIps { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the effective spf sends value.</summary>
    public bool EffectiveSpfSends { get; set; }
    /// <summary>Gets or sets the perm error value.</summary>
    public bool PermError { get; set; }
    /// <summary>Gets or sets the advisory value.</summary>
    public string Advisory { get; set; } = string.Empty;
    /// <summary>Gets or sets the cycle detected value.</summary>
    public bool CycleDetected { get; set; }
    /// <summary>Gets or sets the cycle path value.</summary>
    public string? CyclePath { get; set; }
    /// <summary>Gets or sets the provider help value.</summary>
    public IReadOnlyList<ProviderHelpLinks> ProviderHelp { get; set; } = System.Array.Empty<ProviderHelpLinks>();
}
