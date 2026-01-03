using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class IpEnrichmentWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.IpEnrichmentInfo ip, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (ip == null) throw new ArgumentNullException(nameof(ip));

        var dto = DomainDetective.Reports.SectionProjectors.BuildIpEnrichment(ip);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, ip, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("IP enrichment section could not be projected.");
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.IpEnrichmentSection.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.IpEnrichmentSection sec,
        DomainDetective.Views.IpEnrichmentInfo? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("IP enrichment summarizes the hosting footprint using reverse DNS, ASN/org, and geo hints for discovered IPs.");

        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string, string)> { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2);
        }

        if (sec.Rows.Count > 0)
        {
            headings.AddItem("Enriched IP Rows (Sample)", baseLevel);
            int take = Math.Min(sec.Rows.Count, 200);
            var rt = doc.AddTable(take + 1, 8, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("IP");
            rt.Rows[0].Cells[1].AddParagraph("Family");
            rt.Rows[0].Cells[2].AddParagraph("Source");
            rt.Rows[0].Cells[3].AddParagraph("PTR");
            rt.Rows[0].Cells[4].AddParagraph("ASN");
            rt.Rows[0].Cells[5].AddParagraph("AS Name");
            rt.Rows[0].Cells[6].AddParagraph("CIDR");
            rt.Rows[0].Cells[7].AddParagraph("Geo");

            for (int i = 0; i < take; i++)
            {
                var r = sec.Rows[i];
                var src = $"{r.SourceKind}: {r.SourceHost}";
                var asn = r.Asn.HasValue ? "AS" + r.Asn.Value : "-";
                var geo = string.Join(" ", new[] { r.Country, r.Region }.Where(x => !string.IsNullOrWhiteSpace(x)));
                if (string.IsNullOrWhiteSpace(geo)) geo = "-";
                rt.Rows[i + 1].Cells[0].AddParagraph(r.IpAddress);
                rt.Rows[i + 1].Cells[1].AddParagraph(r.Family.ToString());
                rt.Rows[i + 1].Cells[2].AddParagraph(src);
                rt.Rows[i + 1].Cells[3].AddParagraph(r.Ptr ?? string.Empty);
                rt.Rows[i + 1].Cells[4].AddParagraph(asn);
                rt.Rows[i + 1].Cells[5].AddParagraph(r.AsName ?? string.Empty);
                rt.Rows[i + 1].Cells[6].AddParagraph(r.Cidr ?? string.Empty);
                rt.Rows[i + 1].Cells[7].AddParagraph(geo);
            }

            if (sec.Rows.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Rows.Count} row(s).").SetItalic(true);
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

