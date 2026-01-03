using System;
using System.Globalization;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class DnsAmplificationWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DnsAmplificationSummary amp, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (amp == null) throw new ArgumentNullException(nameof(amp));

        var dto = DomainDetective.Reports.SectionProjectors.BuildDnsAmplification(amp);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, amp, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DNS amplification section could not be projected.");
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DnsAmplificationSection.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.DnsAmplificationSection sec,
        DomainDetective.Views.DnsAmplificationSummary? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Assessment of authoritative name servers for amplification risk signals (open recursion, EDNS behavior, and bounded large-answer probes).");

        var rows = sec.Summary.Count > 0
            ? sec.Summary
            : new System.Collections.Generic.List<(string, string)> { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2);
        }

        if (sec.Servers.Count > 0)
        {
            headings.AddItem("Servers", baseLevel);
            int take = Math.Min(sec.Servers.Count, 200);
            var st = doc.AddTable(take + 1, 11, WordTableStyle.TableGrid);
            st.Rows[0].Cells[0].AddParagraph("Name Server");
            st.Rows[0].Cells[1].AddParagraph("IP");
            st.Rows[0].Cells[2].AddParagraph("Open Recursion");
            st.Rows[0].Cells[3].AddParagraph("EDNS");
            st.Rows[0].Cells[4].AddParagraph("EDNS UDP Size");
            st.Rows[0].Cells[5].AddParagraph("UDP Truncated");
            st.Rows[0].Cells[6].AddParagraph("Worst Type");
            st.Rows[0].Cells[7].AddParagraph("Worst Name");
            st.Rows[0].Cells[8].AddParagraph("Worst Bytes");
            st.Rows[0].Cells[9].AddParagraph("Worst Amp");
            st.Rows[0].Cells[10].AddParagraph("Worst Truncated");

            static string YesNo(bool v) => v ? "Yes" : "No";

            for (int i = 0; i < take; i++)
            {
                var r = sec.Servers[i];
                st.Rows[i + 1].Cells[0].AddParagraph(string.IsNullOrWhiteSpace(r.NameServerHost) ? "-" : r.NameServerHost);
                st.Rows[i + 1].Cells[1].AddParagraph(string.IsNullOrWhiteSpace(r.ServerIp) ? "-" : r.ServerIp);
                st.Rows[i + 1].Cells[2].AddParagraph(YesNo(r.OpenRecursion));
                st.Rows[i + 1].Cells[3].AddParagraph(YesNo(r.EdnsSupported));
                st.Rows[i + 1].Cells[4].AddParagraph(r.EdnsUdpPayloadSize.HasValue ? r.EdnsUdpPayloadSize.Value.ToString(CultureInfo.InvariantCulture) : "-");
                st.Rows[i + 1].Cells[5].AddParagraph(YesNo(r.EdnsTruncatedUdp));
                st.Rows[i + 1].Cells[6].AddParagraph(string.IsNullOrWhiteSpace(r.WorstProbeType) ? "-" : r.WorstProbeType);
                st.Rows[i + 1].Cells[7].AddParagraph(string.IsNullOrWhiteSpace(r.WorstProbeName) ? "-" : r.WorstProbeName);
                st.Rows[i + 1].Cells[8].AddParagraph(r.WorstProbeResponseBytes.ToString(CultureInfo.InvariantCulture));
                st.Rows[i + 1].Cells[9].AddParagraph(r.WorstProbeAmplificationFactor.ToString("0.0", CultureInfo.InvariantCulture) + "x");
                st.Rows[i + 1].Cells[10].AddParagraph(YesNo(r.WorstProbeTruncated));
            }

            if (sec.Servers.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Servers.Count} server(s).").SetItalic(true);
            }
        }

        if (sec.Findings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var f = sec.Findings;
            if (!showInfoFindings)
            {
                f = f.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
            }
            if (f.Count > 0)
            {
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
        }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Positives", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives.Where(x => !string.IsNullOrWhiteSpace(x)).Take(25))
            {
                list.AddItem(p);
            }
            if (sec.Positives.Count > 25)
            {
                doc.AddParagraph($"+{sec.Positives.Count - 25} more positive signal(s).").SetItalic(true);
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

