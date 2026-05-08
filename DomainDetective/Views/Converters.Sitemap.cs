using System;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters {
    /// <summary>Converts sitemap analysis details into a reporting view model.</summary>
    public static SitemapInfo Convert(SitemapAnalysis analysis) {
        if (analysis == null) {
            throw new ArgumentNullException(nameof(analysis));
        }

        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        return new SitemapInfo {
            Check = HealthCheckType.SITEMAP,
            Area = AreaForKind(HealthCheckType.SITEMAP),
            Subject = analysis.Subject,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            SitemapUrls = analysis.SitemapUrls.ToArray(),
            DocumentCount = analysis.Documents.Count,
            UrlCount = analysis.Entries.Count,
            ProbeCount = analysis.UrlProbes.Count,
            DuplicateLocationCount = analysis.DuplicateLocationCount,
            InvalidLocationCount = analysis.InvalidLocationCount,
            RedirectCount = analysis.RedirectCount,
            RedirectLoopCount = analysis.RedirectLoopCount,
            ClientErrorCount = analysis.ClientErrorCount,
            ServerErrorCount = analysis.ServerErrorCount,
            NoIndexCount = analysis.NoIndexCount,
            CanonicalMismatchCount = analysis.CanonicalMismatchCount,
            Documents = analysis.Documents
                .Select(document => new SitemapDocumentInfo {
                    Url = document.Url,
                    StatusCode = document.StatusCode,
                    ContentType = document.ContentType,
                    Present = document.Present,
                    XmlValid = document.XmlValid,
                    SchemaValid = document.SchemaValid,
                    SchemaValidationErrorCount = document.SchemaValidationErrorCount,
                    SchemaValidationError = document.SchemaValidationError,
                    NamespaceValid = document.NamespaceValid,
                    Kind = document.Kind.ToString(),
                    UrlCount = document.UrlCount,
                    SitemapCount = document.SitemapCount,
                    XhtmlAlternateLinkCount = document.XhtmlAlternateLinkCount,
                    Error = document.Error
                })
                .ToArray(),
            ProblemUrls = analysis.UrlProbes
                .Where(probe => probe.RedirectLoop ||
                                probe.WasRedirected ||
                                (probe.StatusCode ?? 0) >= 400 ||
                                probe.NoIndex ||
                                probe.CanonicalMismatch ||
                                !string.IsNullOrWhiteSpace(probe.Error))
                .Take(100)
                .Select(probe => new SitemapUrlProbeInfo {
                    Url = probe.Url,
                    FinalUrl = probe.FinalUrl,
                    StatusCode = probe.StatusCode,
                    ContentType = probe.ContentType,
                    Success = probe.Success,
                    WasRedirected = probe.WasRedirected,
                    RedirectLoop = probe.RedirectLoop,
                    RedirectHopCount = probe.RedirectHopCount,
                    NoIndex = probe.NoIndex,
                    CanonicalUrl = probe.CanonicalUrl,
                    CanonicalMismatch = probe.CanonicalMismatch,
                    Error = probe.Error
                })
                .ToArray(),
            Assessments = analysis.Assessments,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>View model summarizing sitemap XML validation and sitemap-listed URL probes.</summary>
public sealed class SitemapInfo {
    /// <summary>Health check represented by this view.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Analysis area used for grouping.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject that was analyzed.</summary>
    public string? Subject { get; set; }
    /// <summary>Overall status derived from assessments.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Warning assessment count.</summary>
    public int WarningCount { get; set; }
    /// <summary>Error assessment count.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Sitemap URLs discovered and attempted.</summary>
    public string[] SitemapUrls { get; set; } = Array.Empty<string>();
    /// <summary>Number of sitemap documents fetched.</summary>
    public int DocumentCount { get; set; }
    /// <summary>Number of parsed URL entries.</summary>
    public int UrlCount { get; set; }
    /// <summary>Number of URL entries probed.</summary>
    public int ProbeCount { get; set; }
    /// <summary>Number of duplicate loc entries.</summary>
    public int DuplicateLocationCount { get; set; }
    /// <summary>Number of invalid loc entries.</summary>
    public int InvalidLocationCount { get; set; }
    /// <summary>Number of probed URLs that redirected.</summary>
    public int RedirectCount { get; set; }
    /// <summary>Number of probed URLs with redirect loops.</summary>
    public int RedirectLoopCount { get; set; }
    /// <summary>Number of probed URLs returning 4xx.</summary>
    public int ClientErrorCount { get; set; }
    /// <summary>Number of probed URLs returning 5xx.</summary>
    public int ServerErrorCount { get; set; }
    /// <summary>Number of probed URLs marked noindex.</summary>
    public int NoIndexCount { get; set; }
    /// <summary>Number of probed URLs whose canonical differs from the final URL.</summary>
    public int CanonicalMismatchCount { get; set; }
    /// <summary>Fetched sitemap document summaries.</summary>
    public SitemapDocumentInfo[] Documents { get; set; } = Array.Empty<SitemapDocumentInfo>();
    /// <summary>Problem URL probes retained for reporting.</summary>
    public SitemapUrlProbeInfo[] ProblemUrls { get; set; } = Array.Empty<SitemapUrlProbeInfo>();
    /// <summary>Structured assessments emitted by the analysis.</summary>
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Recommendations derived from problem assessments.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Positive findings derived from informational assessments.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Reference URLs used by recommendations.</summary>
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    /// <summary>Raw sitemap analysis object.</summary>
    [JsonIgnore]
    public SitemapAnalysis Raw { get; set; } = new SitemapAnalysis();
}

/// <summary>View model for one fetched sitemap XML document.</summary>
public sealed class SitemapDocumentInfo {
    /// <summary>Sitemap document URL.</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>HTTP status code returned by the sitemap request.</summary>
    public int? StatusCode { get; set; }
    /// <summary>Content type returned by the sitemap request.</summary>
    public string? ContentType { get; set; }
    /// <summary>True when the sitemap returned a successful response.</summary>
    public bool Present { get; set; }
    /// <summary>True when the sitemap XML was well formed.</summary>
    public bool XmlValid { get; set; }
    /// <summary>True when the sitemap XML validates against the official Sitemap protocol schema.</summary>
    public bool SchemaValid { get; set; }
    /// <summary>Number of Sitemap protocol schema validation errors.</summary>
    public int SchemaValidationErrorCount { get; set; }
    /// <summary>First Sitemap protocol schema validation error, when available.</summary>
    public string? SchemaValidationError { get; set; }
    /// <summary>True when the root namespace matches the sitemap protocol namespace.</summary>
    public bool NamespaceValid { get; set; }
    /// <summary>Detected root document kind.</summary>
    public string Kind { get; set; } = string.Empty;
    /// <summary>Number of URL entries in this document.</summary>
    public int UrlCount { get; set; }
    /// <summary>Number of nested sitemap entries in this document.</summary>
    public int SitemapCount { get; set; }
    /// <summary>Number of XHTML alternate links in this document.</summary>
    public int XhtmlAlternateLinkCount { get; set; }
    /// <summary>Fetch or parse error when available.</summary>
    public string? Error { get; set; }
}

/// <summary>View model for one problem sitemap URL probe.</summary>
public sealed class SitemapUrlProbeInfo {
    /// <summary>Original sitemap URL.</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>Final URL after redirects.</summary>
    public string? FinalUrl { get; set; }
    /// <summary>Final HTTP status code.</summary>
    public int? StatusCode { get; set; }
    /// <summary>Final response content type.</summary>
    public string? ContentType { get; set; }
    /// <summary>True when the probe reached a successful response.</summary>
    public bool Success { get; set; }
    /// <summary>True when at least one redirect was observed.</summary>
    public bool WasRedirected { get; set; }
    /// <summary>True when a redirect loop was detected.</summary>
    public bool RedirectLoop { get; set; }
    /// <summary>Number of redirect hops observed.</summary>
    public int RedirectHopCount { get; set; }
    /// <summary>True when the URL was marked noindex.</summary>
    public bool NoIndex { get; set; }
    /// <summary>Canonical URL found in the HTML response.</summary>
    public string? CanonicalUrl { get; set; }
    /// <summary>True when the canonical URL differs from the final URL.</summary>
    public bool CanonicalMismatch { get; set; }
    /// <summary>Probe error when available.</summary>
    public string? Error { get; set; }
}
