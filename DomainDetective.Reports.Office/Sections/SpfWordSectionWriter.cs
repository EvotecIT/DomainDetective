using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes the SPF section into an existing WordDocument. Extracted from SpfWordReport to enable reuse.
/// </summary>
/// <summary>
/// Writes an SPF section into an existing Word document.
/// </summary>
public static class SpfWordSectionWriter
{
    /// <summary>
    /// Writes the SPF section body.
    /// </summary>
    /// <param name="doc">Destination <see cref="WordDocument"/>.</param>
    /// <param name="spf">SPF view model.</param>
    /// <param name="domain">Domain subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Whether to include Info-level findings in tables.</param>
    public static void Write(WordDocument doc, DomainDetective.Views.SpfRecordInfo spf, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (spf == null) throw new ArgumentNullException(nameof(spf));

        // Heading list (TOC-driven) is expected to be created by the caller.
        // We'll add content with simple paragraphs/tables consistent with the original SpfWordReport.

        // Summary
        var summaryTable = doc.AddTable(5, 2, WordTableStyle.TableGrid);
        summaryTable.Rows[0].Cells[0].Paragraphs[0].Text = "Record Present";
        summaryTable.Rows[0].Cells[1].Paragraphs[0].Text = spf.SpfRecordExists ? "Yes" : "No";
        summaryTable.Rows[1].Cells[0].Paragraphs[0].Text = "Starts Correctly";
        summaryTable.Rows[1].Cells[1].Paragraphs[0].Text = spf.StartsCorrectly ? "Yes" : "No";
        summaryTable.Rows[2].Cells[0].Paragraphs[0].Text = "DNS Lookups";
        summaryTable.Rows[2].Cells[1].Paragraphs[0].Text = spf.DnsLookupsCount.ToString();
        summaryTable.Rows[3].Cells[0].Paragraphs[0].Text = "Multiple 'all'";
        summaryTable.Rows[3].Cells[1].Paragraphs[0].Text = spf.MultipleAllMechanisms ? "Yes" : "No";
        summaryTable.Rows[4].Cells[0].Paragraphs[0].Text = "All Mechanism";
        summaryTable.Rows[4].Cells[1].Paragraphs[0].Text = spf.Raw?.AllMechanism ?? string.Empty;

        // Highlights
        if (spf.Highlights != null && spf.Highlights.Count > 0)
        {
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var h in spf.Highlights) list.AddItem(h);
        }

        // Good posture (positives)
        if (scope != ReportScope.Minimal && spf.Positives != null && spf.Positives.Count > 0)
        {
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in spf.Positives.Select(x => x.Title).Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                plist.AddItem(p!);
            }
        }

        // Findings
        var assessAll = spf.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
        var assess = showInfoFindings ? assessAll : assessAll.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assess.Count > 0)
        {
            var table = doc.AddTable(assess.Count + 1, 4, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            table.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            table.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            table.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < assess.Count; i++)
            {
                var a = assess[i];
                table.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity.ToString();
                table.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code ?? string.Empty;
                table.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target ?? string.Empty;
                table.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }
        else
        {
            doc.AddParagraph("No findings.");
        }

        if (scope == ReportScope.Minimal)
        {
            // Minimal stops here
            return;
        }

        // Mechanisms breakdown (Normal/Detailed)
        if (spf.Mechanisms != null && spf.Mechanisms.Count > 0)
        {
            var mechTable = doc.AddTable(spf.Mechanisms.Count + 1, 4, WordTableStyle.TableGrid);
            mechTable.Rows[0].Cells[0].Paragraphs[0].Text = "Qualifier";
            mechTable.Rows[0].Cells[1].Paragraphs[0].Text = "Type";
            mechTable.Rows[0].Cells[2].Paragraphs[0].Text = "Value";
            mechTable.Rows[0].Cells[3].Paragraphs[0].Text = "Provider";
            for (int i = 0; i < spf.Mechanisms.Count; i++)
            {
                var p = spf.Mechanisms[i];
                mechTable.Rows[i + 1].Cells[0].Paragraphs[0].Text = string.IsNullOrEmpty(p.Prefix) ? "+" : p.Prefix;
                mechTable.Rows[i + 1].Cells[1].Paragraphs[0].Text = p.Type ?? string.Empty;
                mechTable.Rows[i + 1].Cells[2].Paragraphs[0].Text = p.Value ?? string.Empty;
                mechTable.Rows[i + 1].Cells[3].Paragraphs[0].Text = p.Provider ?? string.Empty;
            }

            if (scope == ReportScope.Detailed)
            {
                var types = spf.Mechanisms.Select(p => p.Type).Where(t => !string.IsNullOrWhiteSpace(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (types.Count > 0)
                {
                    var exp = doc.AddTable(types.Count + 1, 2, WordTableStyle.TableGrid);
                    exp.Rows[0].Cells[0].Paragraphs[0].Text = "Type";
                    exp.Rows[0].Cells[1].Paragraphs[0].Text = "Meaning";
                    int r = 1;
                    foreach (var t in types)
                    {
                        exp.Rows[r].Cells[0].Paragraphs[0].Text = t!;
                        exp.Rows[r].Cells[1].Paragraphs[0].Text = MechanismMeaning(t!);
                        r++;
                    }
                    var ql = doc.AddList(WordListStyle.Bulleted);
                    ql.AddItem("+ (pass): explicitly allow");
                    ql.AddItem("- (fail): explicitly deny");
                    ql.AddItem("~ (softfail): likely deny");
                    ql.AddItem("? (neutral): no assertion");
                }
            }
        }

        // Evidence (Normal/Detailed)
        var lbl = doc.AddParagraph("SPF Record:");
        lbl.Bold = true;
        var rec = doc.AddParagraph(spf.SpfRecord ?? string.Empty);
        rec.FontSize = 10;
    }

    private static string MechanismMeaning(string type)
    {
        switch (type.ToLowerInvariant())
        {
            case "a": return "Authorize host A/AAAA addresses.";
            case "mx": return "Authorize hosts listed as MX.";
            case "ip4": return "Authorize IPv4 address or CIDR block.";
            case "ip6": return "Authorize IPv6 address or CIDR block.";
            case "include": return "Import another domain's SPF policy.";
            case "exists": return "Authorize based on existence of DNS record.";
            case "ptr": return "Authorize hosts by PTR (discouraged).";
            case "redirect": return "Redirect evaluation to another domain.";
            case "all": return "Catch‑all for remaining senders.";
            case "version": return "SPF version token (v=spf1).";
            default: return "SPF token present.";
        }
    }
}
