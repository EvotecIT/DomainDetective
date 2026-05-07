using System;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public static SitemapSection? BuildSitemap(DomainDetective.Views.SitemapInfo sitemap)
    {
        if (sitemap == null)
        {
            return null;
        }

        var section = new SitemapSection
        {
            Status = string.IsNullOrWhiteSpace(sitemap.Status) ? "-" : sitemap.Status,
            WarningCount = sitemap.WarningCount,
            ErrorCount = sitemap.ErrorCount,
            DocumentCount = sitemap.DocumentCount,
            UrlCount = sitemap.UrlCount,
            ProbeCount = sitemap.ProbeCount,
            DuplicateLocationCount = sitemap.DuplicateLocationCount,
            InvalidLocationCount = sitemap.InvalidLocationCount,
            RedirectCount = sitemap.RedirectCount,
            RedirectLoopCount = sitemap.RedirectLoopCount,
            ClientErrorCount = sitemap.ClientErrorCount,
            ServerErrorCount = sitemap.ServerErrorCount,
            NoIndexCount = sitemap.NoIndexCount,
            CanonicalMismatchCount = sitemap.CanonicalMismatchCount
        };

        section.Summary.Add(("Status", section.Status));
        section.Summary.Add(("Documents", sitemap.DocumentCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("URLs", sitemap.UrlCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Probed URLs", sitemap.ProbeCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Duplicates", sitemap.DuplicateLocationCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Invalid loc", sitemap.InvalidLocationCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Redirects", sitemap.RedirectCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Redirect Loops", sitemap.RedirectLoopCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("HTTP 4xx", sitemap.ClientErrorCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("HTTP 5xx", sitemap.ServerErrorCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Noindex", sitemap.NoIndexCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Canonical Mismatches", sitemap.CanonicalMismatchCount.ToString(CultureInfo.InvariantCulture)));

        foreach (var document in sitemap.Documents ?? Array.Empty<DomainDetective.Views.SitemapDocumentInfo>())
        {
            if (document == null)
            {
                continue;
            }

            section.Documents.Add(new SitemapSection.DocumentRow
            {
                Url = document.Url,
                StatusCode = document.StatusCode,
                ContentType = document.ContentType ?? string.Empty,
                Present = document.Present,
                XmlValid = document.XmlValid,
                NamespaceValid = document.NamespaceValid,
                Kind = document.Kind,
                UrlCount = document.UrlCount,
                SitemapCount = document.SitemapCount,
                Error = document.Error ?? string.Empty
            });
        }

        foreach (var probe in sitemap.ProblemUrls ?? Array.Empty<DomainDetective.Views.SitemapUrlProbeInfo>())
        {
            if (probe == null)
            {
                continue;
            }

            section.ProblemUrls.Add(new SitemapSection.ProblemUrlRow
            {
                Url = probe.Url,
                FinalUrl = probe.FinalUrl ?? string.Empty,
                StatusCode = probe.StatusCode,
                ContentType = probe.ContentType ?? string.Empty,
                Success = probe.Success,
                WasRedirected = probe.WasRedirected,
                RedirectLoop = probe.RedirectLoop,
                RedirectHopCount = probe.RedirectHopCount,
                NoIndex = probe.NoIndex,
                CanonicalUrl = probe.CanonicalUrl ?? string.Empty,
                CanonicalMismatch = probe.CanonicalMismatch,
                Error = probe.Error ?? string.Empty
            });
        }

        foreach (var assessment in (sitemap.Assessments ?? Array.Empty<Assessment>()).Where(a => a != null && a.Severity != AssessmentSeverity.Info))
        {
            section.Findings.Add(new SimpleFinding(
                assessment.Severity.ToString(),
                assessment.Code ?? string.Empty,
                assessment.Target ?? string.Empty,
                assessment.Message ?? string.Empty));
        }

        foreach (var positive in sitemap.Positives ?? Array.Empty<RecommendationAdvice>())
        {
            var text = positive?.Title ?? positive?.Code;
            if (!string.IsNullOrWhiteSpace(text))
            {
                section.Positives.Add(text!);
            }
        }

        foreach (var reference in sitemap.References ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(reference))
            {
                section.References.Add(reference);
            }
        }

        return section;
    }
}
