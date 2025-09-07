using System;
using System.Linq;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HTML writer for MTA-STS section.
/// </summary>
public static class MtastsHtmlSectionWriter
{
    public static void Write(IHtmlComposer html, DomainDetective.Views.MtastsInfo mtasts, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (mtasts == null) throw new ArgumentNullException(nameof(mtasts));

        html.AddHeading($"MTA-STS — {domain}", 2);
        html.AddTable(new [] {
            new { Name = "DNS Policy TXT", Value = mtasts.DnsRecordPresent ? (mtasts.DnsRecordValid ? "Present (valid)" : "Present (invalid)") : "Missing" },
            new { Name = "Policy File", Value = mtasts.PolicyPresent ? (mtasts.PolicyValid ? "Present (valid)" : "Present (invalid)") : "Missing" },
            new { Name = "Mode", Value = mtasts.Mode ?? string.Empty },
            new { Name = "Max-Age", Value = mtasts.MaxAge.ToString() },
            new { Name = "MX Aligned", Value = mtasts.MxAligned ? "Yes" : "No" },
            new { Name = "Status", Value = mtasts.Status ?? string.Empty }
        });

        if (scope == Reports.ReportScope.Minimal) return;

        if (mtasts.MissingMxFromPolicy != null && mtasts.MissingMxFromPolicy.Length > 0)
        {
            html.AddHeading("MX missing from policy", 3);
            html.AddList(mtasts.MissingMxFromPolicy);
        }
    }
}

