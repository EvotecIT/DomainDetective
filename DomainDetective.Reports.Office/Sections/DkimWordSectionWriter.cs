using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Minimal DKIM section writer. Can be expanded later; provides consistent headings and summary table.
/// </summary>
/// <summary>
/// Writes a DKIM section into an existing Word report.
/// </summary>
public static class DkimWordSectionWriter
{
    /// <summary>
    /// Writes DKIM section.
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="dkim">DKIM views for all selectors.</param>
    /// <param name="domain">Domain subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Include Info-level findings.</param>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, System.Collections.Generic.IReadOnlyList<DomainDetective.Views.DkimRecordInfo> dkim, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (dkim == null) throw new ArgumentNullException(nameof(dkim));

        if (dkim.Count == 0)
        {
            doc.AddParagraph("No DKIM selectors discovered.");
            return;
        }

        if (includeNarrative)
        {
            var nar = dkim.FirstOrDefault()?.Narrative;
            if (nar != null)
            {
                if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
                if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
            }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DKIM selectors discovered and their key properties.");
        var table = doc.AddTable(dkim.Count + 1, 10, WordTableStyle.TableGrid);
        table.Rows[0].Cells[0].Paragraphs[0].Text = "Selector";
        table.Rows[0].Cells[1].Paragraphs[0].Text = "Record";
        table.Rows[0].Cells[2].Paragraphs[0].Text = "Key Bits";
        table.Rows[0].Cells[3].Paragraphs[0].Text = "Alg";
        table.Rows[0].Cells[4].Paragraphs[0].Text = "TTL (s)";
        table.Rows[0].Cells[5].Paragraphs[0].Text = "CNAME Resolved";
        table.Rows[0].Cells[6].Paragraphs[0].Text = "CNAME TTL (s)";
        table.Rows[0].Cells[7].Paragraphs[0].Text = "Key Age";
        table.Rows[0].Cells[8].Paragraphs[0].Text = "Public Key";
        table.Rows[0].Cells[9].Paragraphs[0].Text = "Status";
        for (int i = 0; i < dkim.Count; i++)
        {
            var r = dkim[i];
            table.Rows[i + 1].Cells[0].Paragraphs[0].Text = r.Selector ?? string.Empty;
            table.Rows[i + 1].Cells[1].Paragraphs[0].Text = r.DkimRecordExists ? "Present" : "Missing";
            table.Rows[i + 1].Cells[2].Paragraphs[0].Text = r.PublicKeyExists ? r.KeyLength.ToString() : "-";
            table.Rows[i + 1].Cells[3].Paragraphs[0].Text = r.HashAlgorithm ?? string.Empty;
            table.Rows[i + 1].Cells[4].Paragraphs[0].Text = r.DnsRecordTtl?.ToString() ?? "-";
            table.Rows[i + 1].Cells[5].Paragraphs[0].Text = r.IsCnameResolved ? "Yes" : "No";
            table.Rows[i + 1].Cells[6].Paragraphs[0].Text = r.CnameTtl?.ToString() ?? "-";
            table.Rows[i + 1].Cells[7].Paragraphs[0].Text = r.KeyAgeDays > 0 ? r.KeyAgeDays.ToString() : "-";
            table.Rows[i + 1].Cells[8].Paragraphs[0].Text = r.PublicKeyExists ? "Yes" : "No";
            table.Rows[i + 1].Cells[9].Paragraphs[0].Text = r.Status ?? string.Empty;
        }

        if (scope == ReportScope.Minimal) return;

        // Good posture (positives aggregated)
        if (scope != ReportScope.Minimal)
        {
            var positives = dkim.SelectMany(x => x.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                                .Select(p => p.Title)
                                .Where(t => !string.IsNullOrWhiteSpace(t))
                                .Distinct()
                                .ToList();
            if (positives.Count > 0)
            {
                headings.AddItem("Good posture", baseLevel);
                doc.AddParagraph("This domain demonstrates the following positive posture:");
                var plist = doc.AddList(WordListStyle.Bulleted);
                foreach (var t in positives) plist.AddItem(t!);
            }
        }

        // Findings (summarized)
        var findings = dkim.SelectMany(x => x.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings) findings = findings.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (findings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(findings.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            ft.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            ft.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            ft.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < findings.Count; i++)
            {
                var a = findings[i];
                ft.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity.ToString();
                ft.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code ?? string.Empty;
                ft.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target ?? string.Empty;
                ft.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }

        // Evidence
        headings.AddItem("Evidence", baseLevel);
        doc.AddParagraph("Raw DKIM TXT records and key snippets by selector.");
        foreach (var r in dkim)
        {
            if (string.IsNullOrWhiteSpace(r?.Selector)) continue;
            var selector = r!.Selector!;
            var sl = doc.AddParagraph($"Selector: {selector}");
            sl.Bold = true;
            if (!string.IsNullOrWhiteSpace(r.DkimRecord))
            {
                var rl = doc.AddParagraph("Record:"); rl.Bold = true;
                var rp = doc.AddParagraph(r.DkimRecord);
                rp.FontSize = 10;
            }
            if (!string.IsNullOrWhiteSpace(r.PublicKey))
            {
                var kl = doc.AddParagraph("Public Key (snippet):"); kl.Bold = true;
                var key = r.PublicKey!.Length > 120 ? r.PublicKey.Substring(0, 120) + "…" : r.PublicKey;
                var kp = doc.AddParagraph(key);
                kp.FontSize = 10;
            }
        }

        // Highlights / Positives / Recommendations (Detailed only)
        if (scope == ReportScope.Detailed)
        {
            var hl = dkim.SelectMany(x => x.Highlights ?? Array.Empty<string>()).Distinct().ToList();
            if (hl.Count > 0)
            {
                headings.AddItem("Highlights", baseLevel);
                doc.AddParagraph("Notable observations:");
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var h in hl) list.AddItem(h);
            }

            // Recommendations from assessments grouped by code
            var grouped = DomainDetective.RecommendationEngine.GroupByCode(findings);
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

        // References (union across selectors)
        var refs = dkim.SelectMany(d => d.References ?? Array.Empty<string>())
                       .Where(r => !string.IsNullOrWhiteSpace(r))
                       .Distinct(StringComparer.OrdinalIgnoreCase)
                       .ToList();
        if (refs.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, refs);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DkimSection for common data, preserving Word-only extras.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.DkimSection sec,
        System.Collections.Generic.IReadOnlyList<DomainDetective.Views.DkimRecordInfo>? original,
        string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        var first = original?.FirstOrDefault();
        if (includeNarrative && first?.Narrative != null)
        {
            var nar = first.Narrative;
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        // Include TTL for selectors when available (parity with Markdown/HTML/Excel)
        var table = doc.AddTable(Math.Max(sec.Rows.Count, 0) + 1, 7, WordTableStyle.TableGrid);
        table.Rows[0].Cells[0].Paragraphs[0].Text = "Selector";
        table.Rows[0].Cells[1].Paragraphs[0].Text = "Key Bits";
        table.Rows[0].Cells[2].Paragraphs[0].Text = "Alg";
        table.Rows[0].Cells[3].Paragraphs[0].Text = "TTL (s)";
        table.Rows[0].Cells[4].Paragraphs[0].Text = "CNAME Resolved";
        table.Rows[0].Cells[5].Paragraphs[0].Text = "CNAME TTL (s)";
        table.Rows[0].Cells[6].Paragraphs[0].Text = "Status";
        for (int i = 0; i < sec.Rows.Count; i++)
        {
            var r = sec.Rows[i];
            table.Rows[i + 1].Cells[0].Paragraphs[0].Text = r.Selector;
            table.Rows[i + 1].Cells[1].Paragraphs[0].Text = string.IsNullOrWhiteSpace(r.KeyBits) ? "-" : r.KeyBits;
            table.Rows[i + 1].Cells[2].Paragraphs[0].Text = string.IsNullOrWhiteSpace(r.Hash) ? "-" : r.Hash;
            table.Rows[i + 1].Cells[3].Paragraphs[0].Text = r.TtlSeconds.HasValue ? r.TtlSeconds.Value.ToString() : "-";
            table.Rows[i + 1].Cells[4].Paragraphs[0].Text = r.CnameResolved ? "Yes" : "No";
            table.Rows[i + 1].Cells[5].Paragraphs[0].Text = r.CnameTtlSeconds?.ToString() ?? "-";
            table.Rows[i + 1].Cells[6].Paragraphs[0].Text = string.IsNullOrWhiteSpace(r.Status) ? "-" : r.Status;
        }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives) list.AddItem(p);
        }

        var f = sec.Findings;
        if (!showInfoFindings)
            f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
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

        // Evidence from original
        if (original != null && original.Count > 0)
        {
            headings.AddItem("Evidence", baseLevel);
            foreach (var r in original)
            {
                if (string.IsNullOrWhiteSpace(r?.Selector)) continue;
                var selector = r!.Selector!;
                var sl = doc.AddParagraph($"Selector: {selector}"); sl.Bold = true;
                if (!string.IsNullOrWhiteSpace(r.DkimRecord)) { var rl = doc.AddParagraph("Record:"); rl.Bold = true; var rp = doc.AddParagraph(r.DkimRecord); rp.FontSize = 10; }
                if (!string.IsNullOrWhiteSpace(r.PublicKey)) { var kl = doc.AddParagraph("Public Key (snippet):"); kl.Bold = true; var key = r.PublicKey!.Length > 120 ? r.PublicKey.Substring(0, 120) + "…" : r.PublicKey; var kp = doc.AddParagraph(key); kp.FontSize = 10; }
            }
        }

        var refs = sec.References;
        if (refs.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, refs);
        }
    }
}
