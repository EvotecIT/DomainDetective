using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>
    /// Combines CertificateInfo and HttpInfo into a single WebsiteInfo object for PS convenience.
    /// </summary>
    public static WebsiteInfo CombineWebsite(CertificateInfo cert, HttpInfo http)
    {
        var allAssessments = new List<Assessment>();
        if (cert?.Assessments != null) allAssessments.AddRange(cert.Assessments);
        if (http?.Assessments != null) allAssessments.AddRange(http.Assessments);

        Summarize(allAssessments, out var warnCount, out var errCount, out var status);
        var recs = new List<RecommendationAdvice>();
        if (cert?.Recommendations != null) recs.AddRange(cert.Recommendations);
        if (http?.Recommendations != null) recs.AddRange(http.Recommendations);

        var positives = RecommendationEngine.FromPositives(allAssessments);
        var references = BuildReferences(System.Array.Empty<StandardReference>(), recs);

        var subject = cert?.Subject ?? http?.Subject;
        var certGrade = cert != null ? cert.Grade.ToLetter() : string.Empty;
        var httpGrade = http != null ? http.Grade.ToLetter() : string.Empty;
        var hsts = http?.HstsPresent ?? false;
        var mixed = http?.MixedContentDetected ?? false;

        return new WebsiteInfo {
            Check = HealthCheckType.WEBSITE,
            Area = AreaForKind(HealthCheckType.WEBSITE),
            Subject = subject,
            Certificate = cert,
            Http = http,
            CertificateGrade = cert?.Grade ?? GradeLevel.Unknown,
            HttpGrade = http?.Grade ?? GradeLevel.Unknown,
            HstsPresent = hsts,
            MixedContentDetected = mixed,
            Assessments = allAssessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"Cert {certGrade}; Http {httpGrade}; HSTS {(hsts ? "yes" : "no")}; Mixed {(mixed ? "yes" : "no")} ",
            Recommendations = recs,
            Positives = positives,
            References = references
        };
    }
}

public class WebsiteInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public CertificateInfo Certificate { get; set; }
    public HttpInfo Http { get; set; }
    public GradeLevel CertificateGrade { get; set; }
    public GradeLevel HttpGrade { get; set; }
    public bool HstsPresent { get; set; }
    public bool MixedContentDetected { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
}
