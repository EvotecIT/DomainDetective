using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes a DNSBL summary section into an existing Word report.
/// </summary>
public static class DnsblWordSectionWriter
{
    /// <summary>
    /// Writes DNSBL section.
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="dnsbl">DNSBL view model.</param>
    /// <param name="domain">Subject domain.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Include Info-level findings.</param>
    public static void Write(WordDocument doc, DomainDetective.Views.DnsblInfo dnsbl, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (dnsbl == null) throw new ArgumentNullException(nameof(dnsbl));

        var t = doc.AddTable(5, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "Providers";
        t.Rows[0].Cells[1].Paragraphs[0].Text = dnsbl.ProvidersChecked.ToString();
        t.Rows[1].Cells[0].Paragraphs[0].Text = "Hosts Checked";
        t.Rows[1].Cells[1].Paragraphs[0].Text = dnsbl.HostsChecked.ToString();
        t.Rows[2].Cells[0].Paragraphs[0].Text = "Hosts Listed";
        t.Rows[2].Cells[1].Paragraphs[0].Text = dnsbl.HostsListed.ToString();
        t.Rows[3].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[3].Cells[1].Paragraphs[0].Text = dnsbl.Status ?? string.Empty;
        t.Rows[4].Cells[0].Paragraphs[0].Text = "Summary";
        t.Rows[4].Cells[1].Paragraphs[0].Text = dnsbl.Summary ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Listed records (if any)
        var listed = dnsbl.ListedRecords?.ToList() ?? new System.Collections.Generic.List<DomainDetective.DNSBLRecord>();
        if (listed.Count > 0)
        {
            var lt = doc.AddTable(listed.Count + 1, 3, WordTableStyle.TableGrid);
            lt.Rows[0].Cells[0].Paragraphs[0].Text = "Host";
            lt.Rows[0].Cells[1].Paragraphs[0].Text = "Blacklist";
            lt.Rows[0].Cells[2].Paragraphs[0].Text = "Reason";
            for (int i = 0; i < listed.Count; i++)
            {
                var r = listed[i];
                lt.Rows[i + 1].Cells[0].Paragraphs[0].Text = r.SourceHost ?? r.IpAddress;
                lt.Rows[i + 1].Cells[1].Paragraphs[0].Text = r.BlackList ?? string.Empty;
                lt.Rows[i + 1].Cells[2].Paragraphs[0].Text = r.ReplyMeaning ?? string.Empty;
            }
        }
    }
}
