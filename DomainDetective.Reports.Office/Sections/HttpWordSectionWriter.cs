using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class HttpWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.HttpInfo http, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (http == null) throw new ArgumentNullException(nameof(http));

        var dto = DomainDetective.Reports.SectionProjectors.BuildHttp(http);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, http, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("HTTP section could not be projected.");
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.HttpSection.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.HttpSection sec,
        DomainDetective.Views.HttpInfo? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("HTTP reachability and security header posture.");

        var summaryRows = sec.Summary.Count > 0 ? sec.Summary : new List<(string, string)> { ("Status", sec.Status) };
        var t = doc.AddTable(summaryRows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < summaryRows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(summaryRows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(summaryRows[i].Item2);
        }

        try
        {
            var visited = original?.Raw?.VisitedUrls;
            if (visited != null && visited.Count > 0)
            {
                headings.AddItem("Redirect Chain", baseLevel);
                var rt = doc.AddTable(visited.Count + 1, 2, WordTableStyle.TableGrid);
                rt.Rows[0].Cells[0].AddParagraph("Step");
                rt.Rows[0].Cells[1].AddParagraph("URL");
                for (int i = 0; i < visited.Count; i++)
                {
                    rt.Rows[i + 1].Cells[0].AddParagraph((i + 1).ToString());
                    rt.Rows[i + 1].Cells[1].AddParagraph(visited[i] ?? string.Empty);
                }
            }
        }
        catch
        {
        }

        string TrimValue(string? value, int max)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            if (value.Length <= max) return value;
            return value.Substring(0, max) + " …";
        }

        if (sec.PresentSecurityHeaders.Count > 0)
        {
            headings.AddItem("Present Security Headers", baseLevel);
            int take = Math.Min(sec.PresentSecurityHeaders.Count, 50);
            var ht = doc.AddTable(take + 1, 2, WordTableStyle.TableGrid);
            ht.Rows[0].Cells[0].AddParagraph("Header");
            ht.Rows[0].Cells[1].AddParagraph("Value");
            for (int i = 0; i < take; i++)
            {
                var h = sec.PresentSecurityHeaders[i];
                ht.Rows[i + 1].Cells[0].AddParagraph(h.Name);
                ht.Rows[i + 1].Cells[1].AddParagraph(TrimValue(h.Value, 500));
            }
            if (sec.PresentSecurityHeaders.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.PresentSecurityHeaders.Count} header(s).").SetItalic(true);
            }
        }

        if (sec.MissingSecurityHeaders.Count > 0)
        {
            headings.AddItem("Missing Security Headers", baseLevel);
            int take = Math.Min(sec.MissingSecurityHeaders.Count, 50);
            var mt = doc.AddTable(take + 1, 1, WordTableStyle.TableGrid);
            mt.Rows[0].Cells[0].AddParagraph("Header");
            for (int i = 0; i < take; i++)
            {
                mt.Rows[i + 1].Cells[0].AddParagraph(sec.MissingSecurityHeaders[i]);
            }
            if (sec.MissingSecurityHeaders.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.MissingSecurityHeaders.Count} missing header(s).").SetItalic(true);
            }
        }

        if (sec.InformationDisclosureHeaders.Count > 0)
        {
            headings.AddItem("Information Disclosure Headers", baseLevel);
            int take = Math.Min(sec.InformationDisclosureHeaders.Count, 50);
            var it = doc.AddTable(take + 1, 2, WordTableStyle.TableGrid);
            it.Rows[0].Cells[0].AddParagraph("Header");
            it.Rows[0].Cells[1].AddParagraph("Value");
            for (int i = 0; i < take; i++)
            {
                var h = sec.InformationDisclosureHeaders[i];
                it.Rows[i + 1].Cells[0].AddParagraph(h.Name);
                it.Rows[i + 1].Cells[1].AddParagraph(TrimValue(h.Value, 300));
            }
        }

        if (sec.CachingHeaders.Count > 0)
        {
            headings.AddItem("Caching Headers", baseLevel);
            int take = Math.Min(sec.CachingHeaders.Count, 50);
            var ct = doc.AddTable(take + 1, 2, WordTableStyle.TableGrid);
            ct.Rows[0].Cells[0].AddParagraph("Header");
            ct.Rows[0].Cells[1].AddParagraph("Value");
            for (int i = 0; i < take; i++)
            {
                var h = sec.CachingHeaders[i];
                ct.Rows[i + 1].Cells[0].AddParagraph(h.Name);
                ct.Rows[i + 1].Cells[1].AddParagraph(TrimValue(h.Value, 300));
            }
        }

        if (sec.DeprecatedPresent.Count > 0 || sec.DeprecatedMissing.Count > 0)
        {
            headings.AddItem("Deprecated Header Signals", baseLevel);
            var rows = new List<(string Key, string Value)>();
            rows.Add(("Deprecated Present", sec.DeprecatedPresent.Count > 0 ? string.Join(", ", sec.DeprecatedPresent) : "-"));
            rows.Add(("Deprecated Missing", sec.DeprecatedMissing.Count > 0 ? string.Join(", ", sec.DeprecatedMissing) : "-"));
            var dt = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
            for (int i = 0; i < rows.Count; i++)
            {
                dt.Rows[i].Cells[0].AddParagraph(rows[i].Key);
                dt.Rows[i].Cells[1].AddParagraph(rows[i].Value);
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
            foreach (var r in sec.References)
            {
                if (!string.IsNullOrWhiteSpace(r))
                {
                    list.AddItem(r);
                }
            }
        }
    }
}

