using System;

namespace DomainDetective.Reports.Html;

public static class MxHtmlSectionWriter
{
    public static void Write(IHtmlComposer html, DomainDetective.Views.MxInfo mx, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (mx == null) throw new ArgumentNullException(nameof(mx));

        html.AddHeading($"MX — {domain}", 2);
        html.AddTable(new[] {
            new { Name = "MX Records", Value = (mx.MxRecords?.Count ?? 0).ToString() },
            new { Name = "Priorities In Order", Value = mx.PrioritiesInOrder ? "Yes" : "No" },
            new { Name = "Backup Servers", Value = mx.HasBackupServers ? "Yes" : "No" },
            new { Name = "IPv6 Supported", Value = mx.Ipv6Supported ? "Yes" : "No" },
            new { Name = "TTL Uniform", Value = mx.MxTtlUniform ? "Yes" : "No" },
            new { Name = "NS RRset Consistent", Value = mx.MxRrsetConsistentAcrossNs ? "Yes" : "No" },
            new { Name = "Status", Value = mx.Status ?? string.Empty },
        });

        if (scope == Reports.ReportScope.Detailed && mx.MxRecords != null && mx.MxRecords.Count > 0)
        {
            html.AddHeading("Evidence", 3);
            html.AddList(mx.MxRecords);
        }
    }
}

