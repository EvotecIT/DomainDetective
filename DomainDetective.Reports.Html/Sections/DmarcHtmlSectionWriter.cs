using System;
using System.Linq;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HTML writer for DMARC section.
/// </summary>
public static class DmarcHtmlSectionWriter
{
    /// <summary>Writes DMARC section.</summary>
    public static void Write(IHtmlComposer html, DomainDetective.Views.DmarcRecordInfo dmarc, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (dmarc == null) throw new ArgumentNullException(nameof(dmarc));

        html.AddHeading($"DMARC — {domain}", 2);
        html.AddTable(new[] {
            new { Name = "Record Present", Value = dmarc.DmarcRecordExists ? "Yes" : "No" },
            new { Name = "Policy", Value = dmarc.Policy ?? string.Empty },
            new { Name = "adkim/aspf", Value = $"{dmarc.DkimAlignment ?? "?"}/{dmarc.SpfAlignment ?? "?"}" },
            new { Name = "pct", Value = dmarc.Percent ?? string.Empty },
            new { Name = "rua", Value = (dmarc.MailtoRua?.Count ?? 0).ToString() },
            new { Name = "ruf", Value = (dmarc.MailtoRuf?.Count ?? 0).ToString() },
            new { Name = "Status", Value = dmarc.Status ?? string.Empty }
        });

        if (scope != Reports.ReportScope.Minimal)
        {
            var hl = dmarc.Highlights ?? Array.Empty<string>();
            if (hl != null && hl.Count > 0)
            {
                html.AddHeading("Highlights", 3);
                html.AddList(hl);
            }

            // Good posture (positives)
            var positives = (dmarc.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                ?.Select(p => p?.Title)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList() ?? new System.Collections.Generic.List<string>();
            if (positives.Count > 0)
            {
                html.AddHeading("Good posture", 3);
                html.AddList(positives);
            }
        }
    }
}
