using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>
    /// Combines CertificateInfo and HttpInfo into a single WebsiteInfo object for PS convenience.
    /// </summary>
    public static WebsiteInfo CombineWebsite(CertificateInfo? cert, HttpInfo? http)
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

/// <summary>Provides website info functionality.</summary>
public class WebsiteInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the certificate value.</summary>
    public CertificateInfo? Certificate { get; set; }
    /// <summary>Gets or sets the http value.</summary>
    public HttpInfo? Http { get; set; }
    /// <summary>Gets or sets the certificate grade value.</summary>
    public GradeLevel CertificateGrade { get; set; }
    /// <summary>Gets or sets the http grade value.</summary>
    public GradeLevel HttpGrade { get; set; }
    /// <summary>Gets or sets the hsts present value.</summary>
    public bool HstsPresent { get; set; }
    /// <summary>Gets or sets the mixed content detected value.</summary>
    public bool MixedContentDetected { get; set; }
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
}
