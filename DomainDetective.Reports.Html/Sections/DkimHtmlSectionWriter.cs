using System;
using System.Linq;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HTML writer for DKIM section.
/// </summary>
public static class DkimHtmlSectionWriter
{
    /// <summary>Writes DKIM section.</summary>
    public static void Write(IHtmlComposer html, System.Collections.Generic.IReadOnlyList<DomainDetective.Views.DkimRecordInfo> dkim, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (dkim == null) throw new ArgumentNullException(nameof(dkim));

        html.AddHeading($"DKIM — {domain}", 2);
        if (dkim.Count == 0)
        {
            html.AddParagraph("No DKIM selectors discovered.");
            return;
        }
        var rows = dkim.Select(x => new { x.Selector, Record = x.DkimRecordExists ? "Present" : "Missing", Bits = x.PublicKeyExists ? x.KeyLength.ToString() : "-", Alg = x.HashAlgorithm ?? "", AgeDays = x.KeyAgeDays, Status = x.Status });
        html.AddTable(rows);

        if (scope != Reports.ReportScope.Minimal)
        {
            var highlights = dkim.SelectMany(x => x.Highlights ?? Array.Empty<string>()).Distinct().ToList();
            if (highlights.Count > 0)
            {
                html.AddHeading("Highlights", 3);
                html.AddList(highlights);
            }

            // Good posture (positives) merged across selectors
            var positives = dkim
                .SelectMany(x => x.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                .Select(p => p?.Title)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (positives.Count > 0)
            {
                html.AddHeading("Good posture", 3);
                html.AddList(positives);
            }
        }
    }
}
