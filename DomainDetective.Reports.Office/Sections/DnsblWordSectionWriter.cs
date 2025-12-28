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
    /// Writes DNSBL section with standardized headings (Summary, Findings, Evidence, References).
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="headings">Headings list (TOC).</param>
    /// <param name="baseLevel">Base heading level under the DNSBL node.</param>
    /// <param name="dnsbl">DNSBL view model.</param>
    /// <param name="domain">Subject domain.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Include Info-level findings.</param>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DnsblInfo dnsbl, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (dnsbl == null) throw new ArgumentNullException(nameof(dnsbl));
        // Summary
        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DNSBL posture summary for this domain.");
        var t = doc.AddTable(5, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Providers");
        t.Rows[0].Cells[1].AddParagraph(dnsbl.ProvidersChecked.ToString());
        t.Rows[1].Cells[0].AddParagraph("Hosts Checked");
        t.Rows[1].Cells[1].AddParagraph(dnsbl.HostsChecked.ToString());
        t.Rows[2].Cells[0].AddParagraph("Hosts Listed");
        t.Rows[2].Cells[1].AddParagraph(dnsbl.HostsListed.ToString());
        t.Rows[3].Cells[0].AddParagraph("Status");
        t.Rows[3].Cells[1].AddParagraph(dnsbl.Status ?? string.Empty);
        t.Rows[4].Cells[0].AddParagraph("Inline Summary");
        t.Rows[4].Cells[1].AddParagraph(dnsbl.Summary ?? string.Empty);

        // Good posture
        if (scope != ReportScope.Minimal && dnsbl.Positives != null && dnsbl.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in dnsbl.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = dnsbl.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(assessments.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < assessments.Count; i++)
            {
                var a = assessments[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity.ToString());
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }
        else
        {
            doc.AddParagraph("No findings.");
        }

        if (scope == ReportScope.Minimal) return;

        // Listed records (if any)
        var listed = dnsbl.ListedRecords?.ToList() ?? new System.Collections.Generic.List<DomainDetective.DNSBLRecord>();
        headings.AddItem("Evidence", baseLevel);
        doc.AddParagraph(listed.Count > 0 ? "Hosts reported by DNSBL providers:" : "No DNSBL listings observed.");
        if (listed.Count > 0)
        {
            var lt = doc.AddTable(listed.Count + 1, 3, WordTableStyle.TableGrid);
            lt.Rows[0].Cells[0].AddParagraph("Host");
            lt.Rows[0].Cells[1].AddParagraph("Blacklist");
            lt.Rows[0].Cells[2].AddParagraph("Reason");
            for (int i = 0; i < listed.Count; i++)
            {
                var r = listed[i];
                lt.Rows[i + 1].Cells[0].AddParagraph(r.SourceHost ?? r.IpAddress ?? string.Empty);
                lt.Rows[i + 1].Cells[1].AddParagraph(r.BlackList ?? string.Empty);
                lt.Rows[i + 1].Cells[2].AddParagraph(r.ReplyMeaning ?? string.Empty);
            }
        }

        // References
        if (dnsbl.References != null && dnsbl.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, dnsbl.References);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DnsblSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.DnsblSection sec,
        DomainDetective.Views.DnsblInfo? original,
        string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string,string)>()
        { ("Status", sec.Status), ("Providers Checked", sec.ProvidersChecked.ToString()), ("Hosts Checked", sec.HostsChecked.ToString()), ("Hosts Listed", sec.HostsListed.ToString()) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<rows.Count;i++){ t.Rows[i].Cells[0].AddParagraph(rows[i].Item1); t.Rows[i].Cells[1].AddParagraph(rows[i].Item2); }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives) list.AddItem(p);
        }

        var f = sec.Findings; if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message); }
        }

        var listedRecords = original?.ListedRecords;
        if (scope != ReportScope.Minimal && listedRecords != null && listedRecords.Count > 0)
        {
            headings.AddItem("Evidence", baseLevel);
            var lt = doc.AddTable(listedRecords.Count + 1, 3, WordTableStyle.TableGrid);
            lt.Rows[0].Cells[0].AddParagraph("Host");
            lt.Rows[0].Cells[1].AddParagraph("Blacklist");
            lt.Rows[0].Cells[2].AddParagraph("Reason");
            for (int i=0;i<listedRecords.Count;i++){ var r = listedRecords[i]; lt.Rows[i+1].Cells[0].AddParagraph(r.SourceHost ?? r.IpAddress ?? string.Empty); lt.Rows[i+1].Cells[1].AddParagraph(r.BlackList ?? string.Empty); lt.Rows[i+1].Cells[2].AddParagraph(r.ReplyMeaning ?? string.Empty);}
        }

        if (sec.References.Count > 0)
        { headings.AddItem("References", baseLevel); WordLinkHelpers.AddReferencesList(doc, sec.References); }
    }
}
