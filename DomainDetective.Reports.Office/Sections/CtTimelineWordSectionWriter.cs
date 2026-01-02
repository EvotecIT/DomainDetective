using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class CtTimelineWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.CtTimelineInfo ct, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (ct == null) throw new ArgumentNullException(nameof(ct));

        var dto = DomainDetective.Reports.SectionProjectors.BuildCtTimeline(ct);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, ct, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("CT timeline section could not be projected.");
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.CtTimelineSection.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.CtTimelineSection sec,
        DomainDetective.Views.CtTimelineInfo? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Certificate transparency timeline for issuance patterns, issuer diversity, and validity state.");

        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string, string)> { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2);
        }

        if (sec.Timeline.Count > 0)
        {
            headings.AddItem("Timeline (Monthly)", baseLevel);
            int take = Math.Min(sec.Timeline.Count, 120);
            var tt = doc.AddTable(take + 1, 3, WordTableStyle.TableGrid);
            tt.Rows[0].Cells[0].AddParagraph("Month");
            tt.Rows[0].Cells[1].AddParagraph("Certificates");
            tt.Rows[0].Cells[2].AddParagraph("Issuers");
            for (int i = 0; i < take; i++)
            {
                var r = sec.Timeline[i];
                tt.Rows[i + 1].Cells[0].AddParagraph(r.Month);
                tt.Rows[i + 1].Cells[1].AddParagraph(r.Certificates.ToString());
                tt.Rows[i + 1].Cells[2].AddParagraph(r.Issuers.ToString());
            }
            if (sec.Timeline.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Timeline.Count} timeline bucket(s).").SetItalic(true);
            }
        }

        if (sec.RecentCertificates.Count > 0)
        {
            headings.AddItem("Recent Certificates (Sample)", baseLevel);
            int take = Math.Min(sec.RecentCertificates.Count, 200);
            var rt = doc.AddTable(take + 1, 6, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("Entry (UTC)");
            rt.Rows[0].Cells[1].AddParagraph("Not After (UTC)");
            rt.Rows[0].Cells[2].AddParagraph("Validity");
            rt.Rows[0].Cells[3].AddParagraph("Wildcard");
            rt.Rows[0].Cells[4].AddParagraph("Issuer");
            rt.Rows[0].Cells[5].AddParagraph("Common Name");
            for (int i = 0; i < take; i++)
            {
                var r = sec.RecentCertificates[i];
                rt.Rows[i + 1].Cells[0].AddParagraph(r.EntryUtc);
                rt.Rows[i + 1].Cells[1].AddParagraph(r.NotAfterUtc);
                rt.Rows[i + 1].Cells[2].AddParagraph(r.Validity.ToString());
                rt.Rows[i + 1].Cells[3].AddParagraph(r.Wildcard ? "Yes" : "No");
                rt.Rows[i + 1].Cells[4].AddParagraph(r.Issuer);
                rt.Rows[i + 1].Cells[5].AddParagraph(r.CommonName);
            }

            if (sec.RecentCertificates.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.RecentCertificates.Count} certificate(s).").SetItalic(true);
            }
        }

        var f = sec.Findings;
        if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
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
            foreach (var r in sec.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }
}

