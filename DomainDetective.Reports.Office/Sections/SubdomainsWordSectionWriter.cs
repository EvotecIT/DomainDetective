using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class SubdomainsWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.SubdomainsInfo sub, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sub == null) throw new ArgumentNullException(nameof(sub));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Subdomain discovery based on certificate transparency (CT) data. Optionally verifies DNS resolution for a bounded subset.");

        var rows = new (string Key, string Value)[]
        {
            ("Status", sub.Status ?? "-"),
            ("Query OK", sub.QuerySucceeded ? "Yes" : "No"),
            ("Subdomains", sub.SubdomainCount.ToString()),
            ("CT Rows", sub.CertificateObservationCount.ToString()),
            ("CT Processing", sub.ResultsCapped ? "Capped" : "OK"),
            ("Issuer Diversity", sub.DistinctIssuerCount.ToString()),
            ("Seen (UTC)", BuildRange(sub.FirstSeenUtc, sub.LastSeenUtc)),
            ("DNS Verification", sub.Raw?.VerifyStillResolves == true ? (sub.ResolutionReduced ? "Capped" : "Yes") : "No")
        };

        var t = doc.AddTable(rows.Length, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Length; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Key);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Value);
        }

        if (!string.IsNullOrWhiteSpace(sub.FailureReason))
        {
            doc.AddParagraph("Failure: " + sub.FailureReason).SetItalic(true);
        }

        // Table of discovered subdomains (bounded)
        if (sub.Subdomains != null && sub.Subdomains.Count > 0)
        {
            headings.AddItem("Discovered Subdomains", baseLevel);
            int take = Math.Min(sub.Subdomains.Count, 200);
            var st = doc.AddTable(take + 1, 4, WordTableStyle.TableGrid);
            st.Rows[0].Cells[0].AddParagraph("Name");
            st.Rows[0].Cells[1].AddParagraph("First Seen (UTC)");
            st.Rows[0].Cells[2].AddParagraph("Last Seen (UTC)");
            st.Rows[0].Cells[3].AddParagraph("Resolution");
            for (int i = 0; i < take; i++)
            {
                var r = sub.Subdomains[i];
                st.Rows[i + 1].Cells[0].AddParagraph(r.Name);
                st.Rows[i + 1].Cells[1].AddParagraph(r.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-");
                st.Rows[i + 1].Cells[2].AddParagraph(r.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-");
                st.Rows[i + 1].Cells[3].AddParagraph(r.ResolutionStatus.ToString());
            }

            if (sub.Subdomains.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sub.Subdomains.Count} discovered subdomains.").SetItalic(true);
            }
        }

        // Findings
        var assessments = sub.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
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

        if (sub.References != null && sub.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in sub.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.SubdomainsSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.SubdomainsSection sec,
        DomainDetective.Views.SubdomainsInfo? original,
        string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string, string)>() { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2);
        }

        if (sec.Rows.Count > 0)
        {
            headings.AddItem("Discovered Subdomains", baseLevel);
            int take = Math.Min(sec.Rows.Count, 200);
            var st = doc.AddTable(take + 1, 4, WordTableStyle.TableGrid);
            st.Rows[0].Cells[0].AddParagraph("Name");
            st.Rows[0].Cells[1].AddParagraph("First Seen (UTC)");
            st.Rows[0].Cells[2].AddParagraph("Last Seen (UTC)");
            st.Rows[0].Cells[3].AddParagraph("Resolution");
            for (int i = 0; i < take; i++)
            {
                var r = sec.Rows[i];
                st.Rows[i + 1].Cells[0].AddParagraph(r.Name);
                st.Rows[i + 1].Cells[1].AddParagraph(r.FirstSeenUtc);
                st.Rows[i + 1].Cells[2].AddParagraph(r.LastSeenUtc);
                st.Rows[i + 1].Cells[3].AddParagraph(r.Resolution);
            }
        }

        var f = sec.Findings;
        if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < f.Count; i++)
            {
                var a = f[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity);
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }

        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in sec.References) list.AddItem(r);
        }
    }

    private static string BuildRange(DateTimeOffset? first, DateTimeOffset? last)
    {
        if (!first.HasValue && !last.HasValue) return "-";
        var a = first?.ToString("yyyy-MM-dd") ?? "-";
        var b = last?.ToString("yyyy-MM-dd") ?? "-";
        return a + " .. " + b;
    }
}
