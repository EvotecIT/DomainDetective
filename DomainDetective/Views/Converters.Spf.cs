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
        var policy = string.IsNullOrWhiteSpace(analysis.AllMechanism) ? "none" : analysis.AllMechanism.ToLowerInvariant();
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
                var ph = new ProviderHelpLinks
                {
                    ProviderName = match.Primary.DisplayName,
                    Dmarc = match.Primary.DmarcHelpUrl,
                    Spf = match.Primary.SpfHelpUrl,
                    Dkim = match.Primary.DkimHelpUrl,
                    MtaSts = match.Primary.MtaStsHelpUrl,
                    TlsRpt = match.Primary.TlsRptHelpUrl,
                    Deliverability = match.Primary.DeliverabilityHelpUrl
                };
                if (ph.HasAny) helpList.Add(ph);
            }
            foreach (var o in match?.OutboundSenders ?? Array.Empty<DomainDetective.Providers.Email.IMailProvider>())
            {
                var ph = new ProviderHelpLinks
                {
                    ProviderName = o.DisplayName,
                    Dmarc = o.DmarcHelpUrl,
                    Spf = o.SpfHelpUrl,
                    Dkim = o.DkimHelpUrl,
                    MtaSts = o.MtaStsHelpUrl,
                    TlsRpt = o.TlsRptHelpUrl,
                    Deliverability = o.DeliverabilityHelpUrl
                };
                if (ph.HasAny) helpList.Add(ph);
            }
        }
        catch { }

        return new SpfRecordInfo
        {
            Check = HealthCheckType.SPF,
            Area = AreaForKind(HealthCheckType.SPF),
            Subject = analysis.Subject,
            SpfRecord = analysis.SpfRecord,
            RecordLength = analysis?.SpfRecord?.Length ?? 0,
            SpfRecordExists = analysis.SpfRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            MultipleSpfRecords = analysis.MultipleSpfRecords,
            DnsLookupsCount = analysis.DnsLookupsCount,
            ExceedsDnsLookups = analysis.ExceedsDnsLookups,
            MultipleAllMechanisms = analysis.MultipleAllMechanisms,
            ExceedsTotalCharacterLimit = analysis.ExceedsTotalCharacterLimit,
            ExceedsCharacterLimit = analysis.ExceedsCharacterLimit,
            UnknownMechanisms = analysis.UnknownMechanisms,
            Mechanisms = analysis.SpfPartAnalyses,
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
}

public class SpfRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string SpfRecord { get; set; }
    public int RecordLength { get; set; }
    public bool SpfRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool MultipleSpfRecords { get; set; }
    public int DnsLookupsCount { get; set; }
    public bool ExceedsDnsLookups { get; set; }
    public bool MultipleAllMechanisms { get; set; }
    public bool ExceedsTotalCharacterLimit { get; set; }
    public bool ExceedsCharacterLimit { get; set; }
    public IReadOnlyList<string> UnknownMechanisms { get; set; }
    public IReadOnlyList<SpfPartAnalysis> Mechanisms { get; set; }
    public IReadOnlyDictionary<string, int> ProviderCounts { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SpfAnalysis Raw { get; set; }
    public DomainDetective.Narratives.SpfNarrative.Sections Narrative { get; set; }
    public IReadOnlyList<string> Highlights { get; set; }
    public IReadOnlyList<ProviderHelpLinks> ProviderHelp { get; set; }
}
