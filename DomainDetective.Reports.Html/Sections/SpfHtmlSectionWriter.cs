using System;
using System.Linq;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HTML writer for SPF section using <see cref="IHtmlComposer"/>.
/// </summary>
public static class SpfHtmlSectionWriter
{
    /// <summary>Writes the SPF section.</summary>
    public static void Write(IHtmlComposer html, DomainDetective.Views.SpfRecordInfo spf, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (spf == null) throw new ArgumentNullException(nameof(spf));

        html.AddHeading($"SPF — {domain}", 2);
        html.AddTable(new[] {
            new { Name = "Record Present", Value = spf.SpfRecordExists ? "Yes" : "No" },
            new { Name = "Starts Correctly", Value = spf.StartsCorrectly ? "Yes" : "No" },
            new { Name = "DNS Lookups", Value = spf.DnsLookupsCount.ToString() },
            new { Name = "Multiple 'all'", Value = spf.MultipleAllMechanisms ? "Yes" : "No" },
        });

        if (scope != Reports.ReportScope.Minimal)
        {
            if (spf.Highlights?.Count > 0)
            {
                html.AddHeading("Highlights", 3);
                html.AddList(spf.Highlights);
            }

            var negatives = spf.Narrative?.Negatives ?? new System.Collections.Generic.List<string>();
            if (negatives.Count > 0)
            {
                html.AddHeading("Negatives", 3);
                html.AddList(negatives);
            }

            // Good posture (positives)
            var positives = spf.Positives?
                .Select(p => p?.Title)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Select(t => t!) // materialize as non-null strings
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
