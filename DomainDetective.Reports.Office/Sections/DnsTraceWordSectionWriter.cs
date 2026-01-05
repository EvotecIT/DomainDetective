using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class DnsTraceWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DnsTraceInfo tr, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (tr == null) throw new ArgumentNullException(nameof(tr));

        var dto = DomainDetective.Reports.SectionProjectors.BuildDnsTrace(tr);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, tr, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DNS trace section could not be projected.");
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DnsTraceSection.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.DnsTraceSection sec,
        DomainDetective.Views.DnsTraceInfo? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Iterative DNS trace from root servers to identify delegation and authoritative resolution issues.");

        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string, string)> { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1 ?? string.Empty);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2 ?? string.Empty);
        }

        if (original != null && original.Queries != null && original.Queries.Count > 0)
        {
            headings.AddItem("Trace Results", baseLevel);
            var q = original.Queries.OrderBy(x => x.RecordType).ToList();
            var qt = doc.AddTable(q.Count + 1, 6, WordTableStyle.TableGrid);
            qt.Rows[0].Cells[0].AddParagraph("Record Type");
            qt.Rows[0].Cells[1].AddParagraph("Status");
            qt.Rows[0].Cells[2].AddParagraph("Final Status");
            qt.Rows[0].Cells[3].AddParagraph("Final Name");
            qt.Rows[0].Cells[4].AddParagraph("Steps");
            qt.Rows[0].Cells[5].AddParagraph("Failure");
            for (int i = 0; i < q.Count; i++)
            {
                var r = q[i];
                qt.Rows[i + 1].Cells[0].AddParagraph(r.RecordType.ToString());
                qt.Rows[i + 1].Cells[1].AddParagraph(r.Status.ToString());
                qt.Rows[i + 1].Cells[2].AddParagraph(r.FinalResponseStatus.ToString());
                var finalName = r.FinalName;
                string finalNameText = string.IsNullOrWhiteSpace(finalName) ? "-" : finalName ?? "-";
                qt.Rows[i + 1].Cells[3].AddParagraph(finalNameText);
                qt.Rows[i + 1].Cells[4].AddParagraph(r.Steps.Count.ToString());
                var failureReason = r.FailureReason;
                string failureReasonText = string.IsNullOrWhiteSpace(failureReason) ? "-" : failureReason ?? "-";
                qt.Rows[i + 1].Cells[5].AddParagraph(failureReasonText);
            }
        }

        if (sec.Rows.Count > 0)
        {
            headings.AddItem("Trace Steps (Sample)", baseLevel);
            int take = Math.Min(sec.Rows.Count, 200);
            var rt = doc.AddTable(take + 1, 9, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("Trace");
            rt.Rows[0].Cells[1].AddParagraph("Kind");
            rt.Rows[0].Cells[2].AddParagraph("Depth");
            rt.Rows[0].Cells[3].AddParagraph("Server");
            rt.Rows[0].Cells[4].AddParagraph("Name");
            rt.Rows[0].Cells[5].AddParagraph("Type");
            rt.Rows[0].Cells[6].AddParagraph("Status");
            rt.Rows[0].Cells[7].AddParagraph("RTT (ms)");
            rt.Rows[0].Cells[8].AddParagraph("Next");
            for (int i = 0; i < take; i++)
            {
                var r = sec.Rows[i];
                rt.Rows[i + 1].Cells[0].AddParagraph(r.TraceType.ToString());
                rt.Rows[i + 1].Cells[1].AddParagraph(r.Kind.ToString());
                rt.Rows[i + 1].Cells[2].AddParagraph(r.Depth.ToString());
                rt.Rows[i + 1].Cells[3].AddParagraph(r.Server);
                rt.Rows[i + 1].Cells[4].AddParagraph(r.Name);
                rt.Rows[i + 1].Cells[5].AddParagraph(r.RecordType.ToString());
                rt.Rows[i + 1].Cells[6].AddParagraph(r.ResponseStatus.ToString());
                rt.Rows[i + 1].Cells[7].AddParagraph(r.RttMs.ToString());
                rt.Rows[i + 1].Cells[8].AddParagraph(r.NextServers);
            }

            if (sec.Rows.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Rows.Count} trace step(s).").SetItalic(true);
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
