using System;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HTML writer for TLS-RPT section.
/// </summary>
public static class TlsRptHtmlSectionWriter
{
    public static void Write(IHtmlComposer html, DomainDetective.Views.TlsRptInfo tlsrpt, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (tlsrpt == null) throw new ArgumentNullException(nameof(tlsrpt));

        html.AddHeading($"TLS-RPT — {domain}", 2);
        html.AddTable(new [] {
            new { Name = "Record Present", Value = tlsrpt.TlsRptRecordExists ? (tlsrpt.StartsCorrectly ? "Yes (v=TLSRPTv1)" : "Yes (invalid start)") : "No" },
            new { Name = "Multiple Records", Value = tlsrpt.MultipleRecords ? "Yes" : "No" },
            new { Name = "mailto: rua", Value = (tlsrpt.MailtoRua?.Count ?? 0).ToString() },
            new { Name = "http: rua", Value = (tlsrpt.HttpRua?.Count ?? 0).ToString() },
            new { Name = "Invalid URIs", Value = (tlsrpt.InvalidRua?.Count ?? 0).ToString() },
            new { Name = "Status", Value = tlsrpt.Status ?? string.Empty }
        });
    }
}

