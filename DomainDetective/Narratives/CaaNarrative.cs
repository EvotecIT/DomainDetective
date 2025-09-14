using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class CaaNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(CAAAnalysis caa)
    {
        var subj = string.IsNullOrWhiteSpace(caa?.Subject) ? "(domain)" : caa.Subject;
        var title = $"CAA Report — {subj}";
        var subtitle = "CAA Assessment";
        var category = "TLS Security";
        var keywords = $"CAA, tls, certificate, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Certificate Authority Authorization (CAA) records specify which certificate authorities may issue certificates and where to report policy violations.";
        var why = "CAA reduces the risk of unauthorized certificates by limiting trusted issuers and providing contacts for violation reporting.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        hi.Add(caa.AnalysisResults.Count > 0 ? "CAA record is published." : "No CAA record is published.");
        if (caa.CanIssueCertificatesForDomain.Any())
            hi.Add($"Authorized CAs: {string.Join(", ", caa.CanIssueCertificatesForDomain)}");
        if (caa.CanIssueWildcardCertificatesForDomain.Any())
            hi.Add($"Wildcard CAs: {string.Join(", ", caa.CanIssueWildcardCertificatesForDomain)}");
        if (caa.ReportViolationEmail.Any())
            hi.Add($"Report tags: {string.Join(", ", caa.ReportViolationEmail)}");

        det.Add($"Valid records: {caa.ValidRecords}");
        det.Add($"Invalid records: {caa.InvalidRecords}");

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc8659"
        };

        try
        {
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(caa.Assessments ?? new List<Assessment>());
        }
        catch (Exception ex)
        {
            var logger = new InternalLogger();
            logger.WriteWarning($"Failed to split assessments for CAA narrative: {ex.Message}");
        }

        return new Sections
        {
            Title = title,
            Subtitle = subtitle,
            Category = category,
            Keywords = keywords,
            Creator = creator,
            Introduction = intro,
            WhyItMatters = why,
            Highlights = hi,
            Details = det,
            References = refs,
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }
}
