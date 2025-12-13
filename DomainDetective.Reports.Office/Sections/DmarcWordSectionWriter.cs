using System;
using OfficeIMO.Word;
using System.Linq;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Minimal DMARC section writer. Provides a stable, reusable section body.
/// </summary>
public static class DmarcWordSectionWriter
{
    /// <summary>
    /// Writes DMARC section into an existing <see cref="WordDocument"/>.
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="dmarc">DMARC view model.</param>
    /// <param name="domain">Domain subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Whether to include Info-level findings.</param>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DmarcRecordInfo dmarc, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (dmarc == null) throw new ArgumentNullException(nameof(dmarc));

        if (includeNarrative)
        {
            var nar = dmarc.Narrative;
            if (nar != null)
            {
                if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
                if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
            }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DMARC record presence, policy, alignment and reporting endpoints.");
        var t = doc.AddTable(8, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "Record Present";
        t.Rows[0].Cells[1].Paragraphs[0].Text = dmarc.DmarcRecordExists ? "Yes" : "No";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "Policy";
        t.Rows[1].Cells[1].Paragraphs[0].Text = dmarc.Policy ?? string.Empty;
        t.Rows[2].Cells[0].Paragraphs[0].Text = "adkim/aspf";
        t.Rows[2].Cells[1].Paragraphs[0].Text = $"{dmarc.DkimAlignment ?? "?"}/{dmarc.SpfAlignment ?? "?"}";
        t.Rows[3].Cells[0].Paragraphs[0].Text = "pct";
        t.Rows[3].Cells[1].Paragraphs[0].Text = dmarc.Percent ?? string.Empty;
        t.Rows[4].Cells[0].Paragraphs[0].Text = "rua";
        t.Rows[4].Cells[1].Paragraphs[0].Text = (dmarc.MailtoRua?.Count ?? 0).ToString();
        t.Rows[5].Cells[0].Paragraphs[0].Text = "ruf";
        t.Rows[5].Cells[1].Paragraphs[0].Text = (dmarc.MailtoRuf?.Count ?? 0).ToString();
        t.Rows[6].Cells[0].Paragraphs[0].Text = "ext auth";
        t.Rows[6].Cells[1].Paragraphs[0].Text = (dmarc.ExternalReportAuthorization?.Count ?? 0).ToString();
        t.Rows[7].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[7].Cells[1].Paragraphs[0].Text = dmarc.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (scope != ReportScope.Minimal && dmarc.Positives != null && dmarc.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in dmarc.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        var assessList = (dmarc.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings)
        {
            assessList = assessList.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        }
        if (assessList.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(assessList.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            ft.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            ft.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            ft.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < assessList.Count; i++)
            {
                var a = assessList[i];
                ft.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity.ToString();
                ft.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code ?? string.Empty;
                ft.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target ?? string.Empty;
                ft.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }

        // Evidence
        headings.AddItem("Evidence", baseLevel);
        doc.AddParagraph("Raw DMARC record and reporting endpoints.");
        var lbl = doc.AddParagraph("DMARC Record:");
        lbl.Bold = true;
        var rec = doc.AddParagraph(dmarc.DmarcRecord ?? string.Empty);
        rec.FontSize = 10;
        // RUA / RUF endpoints
        var anyRua = dmarc.MailtoRua != null && dmarc.MailtoRua.Count > 0;
        var anyRuf = dmarc.MailtoRuf != null && dmarc.MailtoRuf.Count > 0;
        if (anyRua || anyRuf)
        {
            var elist = doc.AddList(WordListStyle.Bulleted);
            if (anyRua)
            {
                var rua = dmarc.MailtoRua?.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? Array.Empty<string>();
                elist.AddItem($"Aggregate RUA: {string.Join(", ", rua)}");
            }
            if (anyRuf)
            {
                var ruf = dmarc.MailtoRuf?.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? Array.Empty<string>();
                elist.AddItem($"Forensic RUF: {string.Join(", ", ruf)}");
            }
        }
        // External report authorization
        if (dmarc.ExternalReportAuthorization != null && dmarc.ExternalReportAuthorization.Count > 0)
        {
            doc.AddParagraph("External reporting authorization:");
            var alist = doc.AddList(WordListStyle.Bulleted);
            foreach (var kv in dmarc.ExternalReportAuthorization)
            {
                alist.AddItem($"{kv.Key}: {(kv.Value ? "authorized" : "denied")}");
            }
        }

        // Detailed extras: highlights and recommendations
        if (scope == ReportScope.Detailed)
        {
            var hl = dmarc.Highlights ?? Array.Empty<string>();
            if (hl != null && hl.Count > 0)
            {
                headings.AddItem("Highlights", baseLevel);
                doc.AddParagraph("Notable observations:");
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var h in hl) list.AddItem(h);
            }
            var grouped = DomainDetective.RecommendationEngine.GroupByCode(assessList);
            var negative = grouped.Where(g => g.MaxSeverity != DomainDetective.AssessmentSeverity.Info).ToList();
            if (negative.Count > 0)
            {
                headings.AddItem("Recommendations", baseLevel);
                var rt = doc.AddTable(negative.Count + 1, 3, WordTableStyle.TableGrid);
                rt.Rows[0].Cells[0].Paragraphs[0].Text = "Code";
                rt.Rows[0].Cells[1].Paragraphs[0].Text = "Title";
                rt.Rows[0].Cells[2].Paragraphs[0].Text = "How";
                for (int i = 0; i < negative.Count; i++)
                {
                    var rv = negative[i];
                    rt.Rows[i + 1].Cells[0].Paragraphs[0].Text = rv.Code ?? string.Empty;
                    rt.Rows[i + 1].Cells[1].Paragraphs[0].Text = rv.Advice?.Title ?? string.Empty;
                    rt.Rows[i + 1].Cells[2].Paragraphs[0].Text = rv.Advice?.How ?? string.Empty;
                }
            }
        }

        // References
        if (dmarc.References != null && dmarc.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, dmarc.References);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DmarcSection for common data, preserving Word-only extras.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.DmarcSection sec,
        DomainDetective.Views.DmarcRecordInfo? original,
        string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        if (includeNarrative && original?.Narrative != null)
        {
            var nar = original.Narrative;
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        // Summary
        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string Key, string Value)>() {
            ("Status", sec.Status), ("Policy", sec.Policy), ("rua", sec.RuaCount.ToString()), ("ruf", sec.RufCount.ToString()) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++) { t.Rows[i].Cells[0].Paragraphs[0].Text = rows[i].Key; t.Rows[i].Cells[1].Paragraphs[0].Text = rows[i].Value; }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives) list.AddItem(p);
        }

        var f = sec.Findings;
        if (!showInfoFindings)
            f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            ft.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            ft.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            ft.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < f.Count; i++)
            {
                var a = f[i];
                ft.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity;
                ft.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code;
                ft.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target;
                ft.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }

        if (original != null)
        {
            // Evidence
            headings.AddItem("Evidence", baseLevel);
            var lbl = doc.AddParagraph("DMARC Record:"); lbl.Bold = true;
            var rec = doc.AddParagraph(original.DmarcRecord ?? string.Empty); rec.FontSize = 10;

            var anyRua = original.MailtoRua != null && original.MailtoRua.Count > 0;
            var anyRuf = original.MailtoRuf != null && original.MailtoRuf.Count > 0;
            if (anyRua || anyRuf)
            {
                var elist = doc.AddList(WordListStyle.Bulleted);
                if (anyRua) elist.AddItem($"Aggregate RUA: {string.Join(", ", original.MailtoRua)}");
                if (anyRuf) elist.AddItem($"Forensic RUF: {string.Join(", ", original.MailtoRuf)}");
            }
        }

        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, sec.References);
        }
    }
}
