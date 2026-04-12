using System;
using System.Linq;

namespace DomainDetective.Reports.Html;

/// <summary>
/// DNSBL section writer for HTML reports via <see cref="IHtmlComposer"/>.
/// </summary>
public static class DnsblHtmlSectionWriter
{
    /// <summary>Writes the HTML report section.</summary>
    public static void Write(IHtmlComposer html, DomainDetective.Views.DnsblInfo dnsbl, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (dnsbl == null) throw new ArgumentNullException(nameof(dnsbl));

        html.AddHeading($"DNSBL — {domain}", 2);
        html.AddTable(new [] {
            new { Name = "Providers", Value = dnsbl.ProvidersChecked.ToString() },
            new { Name = "Hosts Checked", Value = dnsbl.HostsChecked.ToString() },
            new { Name = "Hosts Listed", Value = dnsbl.HostsListed.ToString() },
            new { Name = "Status", Value = dnsbl.Status ?? string.Empty }
        });

        if (scope == Reports.ReportScope.Minimal) return;

        var listed = dnsbl.ListedRecords?.Select(r => new { Host = r.SourceHost ?? r.IpAddress, Blacklist = r.BlackList, Reason = r.ReplyMeaning }).ToList();
        if (listed != null && listed.Count > 0)
        {
            html.AddHeading("Listed Records", 3);
            html.AddTable(listed);
        }
    }
}
