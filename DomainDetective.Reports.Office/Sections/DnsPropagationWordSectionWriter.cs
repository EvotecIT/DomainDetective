using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class DnsPropagationWordSectionWriter
{
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        IReadOnlyList<DomainDetective.Views.DnsPropagationInfo> items,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));

        var list = (items ?? Array.Empty<DomainDetective.Views.DnsPropagationInfo>())
            .Where(i => i != null)
            .OrderBy(i => i.RecordType.ToString(), StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (list.Count == 0)
        {
            headings.AddItem("Summary", baseLevel);
            doc.AddParagraph("No DNS propagation data available.").SetItalic(true);
            return;
        }

	        string TrimValue(string? value, int max)
	        {
	            if (string.IsNullOrEmpty(value)) return string.Empty;
	            if (value.Length <= max) return value;
	            return value.Substring(0, max) + " …";
	        }

        foreach (var dp in list)
        {
            headings.AddItem(dp.RecordType.ToString(), baseLevel);
            doc.AddParagraph("Multi-resolver DNS propagation visibility for this record type.");

            var sec = DomainDetective.Reports.SectionProjectors.BuildDnsPropagation(dp);
            if (sec == null)
            {
                doc.AddParagraph("DNS propagation section could not be projected.").SetItalic(true);
                continue;
            }

            headings.AddItem("Summary", baseLevel + 1);
	            var summaryRows = sec.Summary.Count > 0 ? sec.Summary : new List<(string, string)> { ("Status", sec.Status) };
	            var st = doc.AddTable(summaryRows.Count, 2, WordTableStyle.TableGrid);
	            for (int i = 0; i < summaryRows.Count; i++)
	            {
	                st.Rows[i].Cells[0].AddParagraph(summaryRows[i].Item1 ?? string.Empty);
	                st.Rows[i].Cells[1].AddParagraph(summaryRows[i].Item2 ?? string.Empty);
	            }

            if (sec.AnswerSets.Count > 0)
            {
                headings.AddItem("Answer Sets", baseLevel + 1);
                int take = Math.Min(sec.AnswerSets.Count, 50);
                var at = doc.AddTable(take + 1, 5, WordTableStyle.TableGrid);
                at.Rows[0].Cells[0].AddParagraph("Answer Set");
                at.Rows[0].Cells[1].AddParagraph("Servers");
                at.Rows[0].Cells[2].AddParagraph("Countries");
                at.Rows[0].Cells[3].AddParagraph("Locations");
                at.Rows[0].Cells[4].AddParagraph("Sample Servers");
                for (int i = 0; i < take; i++)
                {
                    var r = sec.AnswerSets[i];
                    at.Rows[i + 1].Cells[0].AddParagraph(TrimValue(r.AnswerSetKey, 200));
                    at.Rows[i + 1].Cells[1].AddParagraph(r.Servers.ToString());
                    at.Rows[i + 1].Cells[2].AddParagraph(r.Countries.ToString());
                    at.Rows[i + 1].Cells[3].AddParagraph(r.Locations.ToString());
                    at.Rows[i + 1].Cells[4].AddParagraph(TrimValue(r.SampleServers, 250));
                }
                if (sec.AnswerSets.Count > take)
                {
                    doc.AddParagraph($"Showing first {take} of {sec.AnswerSets.Count} answer set(s).").SetItalic(true);
                }
            }

            if (sec.Countries.Count > 0)
            {
                headings.AddItem("Country Rollup", baseLevel + 1);
                int take = Math.Min(sec.Countries.Count, 80);
                var ct = doc.AddTable(take + 1, 6, WordTableStyle.TableGrid);
                ct.Rows[0].Cells[0].AddParagraph("Country");
                ct.Rows[0].Cells[1].AddParagraph("Servers");
                ct.Rows[0].Cells[2].AddParagraph("Success");
                ct.Rows[0].Cells[3].AddParagraph("Errors");
                ct.Rows[0].Cells[4].AddParagraph("Majority");
                ct.Rows[0].Cells[5].AddParagraph("Non-Majority");
                for (int i = 0; i < take; i++)
                {
                    var r = sec.Countries[i];
                    ct.Rows[i + 1].Cells[0].AddParagraph(r.Country);
                    ct.Rows[i + 1].Cells[1].AddParagraph(r.Servers.ToString());
                    ct.Rows[i + 1].Cells[2].AddParagraph(r.Success.ToString());
                    ct.Rows[i + 1].Cells[3].AddParagraph(r.Errors.ToString());
                    ct.Rows[i + 1].Cells[4].AddParagraph(r.Majority.ToString());
                    ct.Rows[i + 1].Cells[5].AddParagraph(r.NonMajority.ToString());
                }
                if (sec.Countries.Count > take)
                {
                    doc.AddParagraph($"Showing first {take} of {sec.Countries.Count} country row(s).").SetItalic(true);
                }
            }

            if (sec.Servers.Count > 0)
            {
                headings.AddItem("Resolvers (Sample)", baseLevel + 1);
                int take = Math.Min(sec.Servers.Count, 200);
                var rt = doc.AddTable(take + 1, 10, WordTableStyle.TableGrid);
                rt.Rows[0].Cells[0].AddParagraph("Server IP");
                rt.Rows[0].Cells[1].AddParagraph("Country");
                rt.Rows[0].Cells[2].AddParagraph("Location");
                rt.Rows[0].Cells[3].AddParagraph("ASN");
                rt.Rows[0].Cells[4].AddParagraph("Success");
                rt.Rows[0].Cells[5].AddParagraph("RTT (ms)");
                rt.Rows[0].Cells[6].AddParagraph("Majority");
                rt.Rows[0].Cells[7].AddParagraph("Answer Set");
                rt.Rows[0].Cells[8].AddParagraph("Answers");
                rt.Rows[0].Cells[9].AddParagraph("Error");
                for (int i = 0; i < take; i++)
                {
                    var r = sec.Servers[i];
                    rt.Rows[i + 1].Cells[0].AddParagraph(r.ServerIp);
                    rt.Rows[i + 1].Cells[1].AddParagraph(r.Country);
                    rt.Rows[i + 1].Cells[2].AddParagraph(r.Location);
                    rt.Rows[i + 1].Cells[3].AddParagraph(string.IsNullOrWhiteSpace(r.Asn) ? "-" : "AS" + r.Asn);
                    rt.Rows[i + 1].Cells[4].AddParagraph(r.Success ? "Yes" : "No");
                    rt.Rows[i + 1].Cells[5].AddParagraph(r.DurationMs.ToString());
                    rt.Rows[i + 1].Cells[6].AddParagraph(r.IsMajority ? "Yes" : "No");
                    rt.Rows[i + 1].Cells[7].AddParagraph(TrimValue(r.AnswerSetKey, 120));
                    rt.Rows[i + 1].Cells[8].AddParagraph(TrimValue(r.Answers, 250));
                    rt.Rows[i + 1].Cells[9].AddParagraph(TrimValue(r.Error, 200));
                }
                if (sec.Servers.Count > take)
                {
                    doc.AddParagraph($"Showing first {take} of {sec.Servers.Count} resolver row(s).").SetItalic(true);
                }
            }

            var findings = sec.Findings;
            if (!showInfoFindings)
            {
                findings = findings.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
            }
            if (findings.Count > 0)
            {
                headings.AddItem("Findings", baseLevel + 1);
                var ft = doc.AddTable(findings.Count + 1, 4, WordTableStyle.TableGrid);
                ft.Rows[0].Cells[0].AddParagraph("Severity");
                ft.Rows[0].Cells[1].AddParagraph("Code");
                ft.Rows[0].Cells[2].AddParagraph("Target");
                ft.Rows[0].Cells[3].AddParagraph("Message");
                for (int i = 0; i < findings.Count; i++)
                {
                    var f = findings[i];
                    ft.Rows[i + 1].Cells[0].AddParagraph(f.Severity);
                    ft.Rows[i + 1].Cells[1].AddParagraph(f.Code);
                    ft.Rows[i + 1].Cells[2].AddParagraph(f.Target);
                    ft.Rows[i + 1].Cells[3].AddParagraph(TrimValue(f.Message, 500));
                }
            }

            if (sec.References.Count > 0)
            {
                headings.AddItem("References", baseLevel + 1);
                var refs = doc.AddList(WordListStyle.Bulleted);
                foreach (var r in sec.References)
                {
                    if (!string.IsNullOrWhiteSpace(r))
                    {
                        refs.AddItem(r);
                    }
                }
            }
        }
    }
}
