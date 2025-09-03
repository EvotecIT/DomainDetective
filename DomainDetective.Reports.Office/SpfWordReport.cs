using System;
using System.Linq;
using OfficeIMO.Word;
using DocumentFormat.OpenXml.Wordprocessing;
using DomainDetective.Narratives;

namespace DomainDetective.Reports.Office;

public static class SpfWordReport
{
    public static void Generate(string path, DomainDetective.SpfAnalysis spf, string domain, string? logoPath = null, string? headerText = null, string? footerText = null, string? watermarkText = null, bool showInfoFindings = true)
    {
        using var doc = WordDocument.Create(path);

        // Document settings
        doc.Settings.UpdateFieldsOnOpen = true;

        // Optional cover page and TOC
        try { doc.AddCoverPage(CoverPageTemplate.IonDark); } catch { }
        try { doc.AddTableOfContent(TableOfContentStyle.Template1); } catch { }
        doc.AddPageBreak();

        // Header & footer with page numbers and branding
        doc.AddHeadersAndFooters();
        doc.DifferentFirstPage = false;
        doc.Header.Default.AddParagraph(string.IsNullOrWhiteSpace(headerText) ? $"SPF Report — {domain}" : headerText);
        doc.Header.Default.AddParagraph($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        if (!string.IsNullOrWhiteSpace(logoPath))
        {
            try { doc.Header.Default.AddParagraph().AddImage(logoPath, 48, 48); } catch { }
        }
        var footerTable = doc.Footer.Default.AddTable(1, 2, WordTableStyle.TableGrid);
        footerTable.WidthType = TableWidthUnitValues.Pct; // 5000 = 100%
        footerTable.Width = 5000;
        footerTable.Rows[0].Cells[0].AddParagraph(string.IsNullOrWhiteSpace(footerText) ? "Confidential" : footerText);
        var footerRight = footerTable.Rows[0].Cells[1].AddParagraph();
        footerRight.ParagraphAlignment = JustificationValues.Right;
        footerRight.AddPageNumber(includeTotalPages: true, separator: " / ");
        if (!string.IsNullOrWhiteSpace(watermarkText))
        {
            try { doc.Sections[0].Header.Default.AddWatermark(WordWatermarkStyle.Text, watermarkText); } catch { }
        }

        // Title in header; no body title block

        // Numbered headings list (TOC-driven)
        var headings = doc.AddTableOfContentList(WordListStyle.Headings111);
        headings.AddItem($"SPF Assessment for {domain}");

        // Introduction & Why it matters (business facing)
        var nar = SpfNarrative.Build(spf);
        headings.AddItem("Introduction", 1);
        doc.AddParagraph(nar.Introduction);
        headings.AddItem("Why this matters", 1);
        doc.AddParagraph(nar.WhyItMatters);

        // 1.1 Summary
        headings.AddItem("Summary", 1);
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
        summaryTable.Rows[4].Cells[1].Paragraphs[0].Text = spf.AllMechanism ?? string.Empty;

        // Highlights bullets
        if (nar.Highlights.Count > 0)
        {
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var h in nar.Highlights) list.AddItem(h);
        }

        // 1.2 Findings
        headings.AddItem("Findings", 1);
        var assessAll = spf.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
        var assess = showInfoFindings ? assessAll : assessAll.Where(a => a.Severity != AssessmentSeverity.Info).ToList();
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

        // Mechanisms breakdown
        headings.AddItem("Mechanisms", 1);
        if (spf.SpfPartAnalyses != null && spf.SpfPartAnalyses.Count > 0)
        {
            var mechTable = doc.AddTable(spf.SpfPartAnalyses.Count + 1, 4, WordTableStyle.TableGrid);
            mechTable.Rows[0].Cells[0].Paragraphs[0].Text = "Qualifier";
            mechTable.Rows[0].Cells[1].Paragraphs[0].Text = "Type";
            mechTable.Rows[0].Cells[2].Paragraphs[0].Text = "Value";
            mechTable.Rows[0].Cells[3].Paragraphs[0].Text = "Provider";
            for (int i = 0; i < spf.SpfPartAnalyses.Count; i++)
            {
                var p = spf.SpfPartAnalyses[i];
                mechTable.Rows[i + 1].Cells[0].Paragraphs[0].Text = string.IsNullOrEmpty(p.Prefix) ? "+" : p.Prefix;
                mechTable.Rows[i + 1].Cells[1].Paragraphs[0].Text = p.Type ?? string.Empty;
                mechTable.Rows[i + 1].Cells[2].Paragraphs[0].Text = p.Value ?? string.Empty;
                mechTable.Rows[i + 1].Cells[3].Paragraphs[0].Text = p.Provider ?? string.Empty;
            }

            // Provider summary
            var providers = spf.SpfPartAnalyses
                .Where(p => !string.IsNullOrWhiteSpace(p.Provider))
                .GroupBy(p => p.Provider!)
                .Select(g => $"{g.Key} ({g.Count()})")
                .ToList();
            if (providers.Count > 0)
            {
                var provLine = string.Join(", ", providers);
                var pv = doc.AddParagraph($"Detected providers: {provLine}");
                pv.Italic = true;
            }

            // Mechanism explainer (present types)
            var types = spf.SpfPartAnalyses.Select(p => p.Type).Where(t => !string.IsNullOrWhiteSpace(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (types.Count > 0)
            {
                doc.AddParagraph("Mechanism Explainer");
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
                // Qualifier legend
                var qTitle = doc.AddParagraph("Qualifier Legend");
                var ql = doc.AddList(WordListStyle.Bulleted);
                ql.AddItem("+ (pass): explicitly allow");
                ql.AddItem("- (fail): explicitly deny");
                ql.AddItem("~ (softfail): likely deny, often accepted but marked");
                ql.AddItem("? (neutral): no assertion");
            }
        }

        // 1.3 Evidence
        headings.AddItem("Evidence", 1);
        var lbl = doc.AddParagraph("SPF Record:");
        lbl.Bold = true;
        var rec = doc.AddParagraph(spf.SpfRecord ?? string.Empty);
        rec.FontSize = 10;

        // Mechanisms list
        void AddList(string title, System.Collections.Generic.IEnumerable<string> list)
        {
            var vals = list?.Distinct().ToList();
            if (vals == null || vals.Count == 0) return;
            var t = doc.AddParagraph(title);
            t.Bold = true;
            var wordList = doc.AddList(WordListStyle.Bulleted);
            foreach (var v in vals) wordList.AddItem(v);
        }
        AddList("A", spf.ARecords);
        AddList("MX", spf.MxRecords);
        AddList("IPv4", spf.Ipv4Records);
        AddList("IPv6", spf.Ipv6Records);
        AddList("Include", spf.IncludeRecords);
        AddList("Exists", spf.ExistsRecords);
        AddList("PTR", spf.PtrRecords);

        // Lookups
        headings.AddItem("DNS Lookups", 1);
        if (spf.DnsLookups != null && spf.DnsLookups.Count > 0)
        {
            var lookList = doc.AddList(WordListStyle.Bulleted);
            foreach (var l in spf.DnsLookups.Distinct()) lookList.AddItem(l);
        }

        // Resolved ranges (top 10)
        if (spf.ResolvedIpv4Records != null && spf.ResolvedIpv4Records.Count > 0)
        {
            doc.AddParagraph($"Resolved IPv4 ranges ({spf.ResolvedIpv4Records.Count})");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var cidr in spf.ResolvedIpv4Records.Take(10)) list.AddItem(cidr);
        }
        if (spf.ResolvedIpv6Records != null && spf.ResolvedIpv6Records.Count > 0)
        {
            doc.AddParagraph($"Resolved IPv6 ranges ({spf.ResolvedIpv6Records.Count})");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var cidr in spf.ResolvedIpv6Records.Take(10)) list.AddItem(cidr);
        }

        // Flattened IP Analysis
        var flat = spf.FlattenedIpAnalysis;
        headings.AddItem("Flattened IP Analysis", 1);
        var flatTable = doc.AddTable(3, 2, WordTableStyle.TableGrid);
        flatTable.Rows[0].Cells[0].Paragraphs[0].Text = "Unique IPs";
        flatTable.Rows[0].Cells[1].Paragraphs[0].Text = (flat?.UniqueIps?.Count ?? 0).ToString();
        flatTable.Rows[1].Cells[0].Paragraphs[0].Text = "Duplicate IPs";
        flatTable.Rows[1].Cells[1].Paragraphs[0].Text = (flat?.DuplicateIps?.Count ?? 0).ToString();
        flatTable.Rows[2].Cells[0].Paragraphs[0].Text = "Tokens Resolved";
        flatTable.Rows[2].Cells[1].Paragraphs[0].Text = (flat?.TokenIpMap?.Count ?? 0).ToString();
        if (flat?.TokenIpMap != null && flat.TokenIpMap.Count > 0)
        {
            doc.AddParagraph("Token → IPs (counts)");
            var t = doc.AddTable(flat.TokenIpMap.Count + 1, 2, WordTableStyle.TableGrid);
            t.Rows[0].Cells[0].Paragraphs[0].Text = "Token";
            t.Rows[0].Cells[1].Paragraphs[0].Text = "IP Count";
            int r = 1;
            foreach (var kv in flat.TokenIpMap)
            {
                t.Rows[r].Cells[0].Paragraphs[0].Text = kv.Key;
                t.Rows[r].Cells[1].Paragraphs[0].Text = (kv.Value?.Count ?? 0).ToString();
                r++;
            }
            // Show sample of unique IPs
            doc.AddParagraph("Sample Unique IPs");
            var ipList = doc.AddList(WordListStyle.Bulleted);
            foreach (var ip in flat.UniqueIps.Take(20)) ipList.AddItem(ip);
        }

        // Cycles & Advisory
        headings.AddItem("Policy Checks", 1);
        var checks = doc.AddTable(3, 2, WordTableStyle.TableGrid);
        checks.Rows[0].Cells[0].Paragraphs[0].Text = "Cycle Detected";
        checks.Rows[0].Cells[1].Paragraphs[0].Text = spf.CycleDetected ? "Yes" : "No";
        checks.Rows[1].Cells[0].Paragraphs[0].Text = "Cycle Path";
        checks.Rows[1].Cells[1].Paragraphs[0].Text = spf.CyclePath ?? string.Empty;
        checks.Rows[2].Cells[0].Paragraphs[0].Text = "Advisory";
        checks.Rows[2].Cells[1].Paragraphs[0].Text = spf.Advisory ?? string.Empty;

        // Recommendations
        var recs = spf.Recommendations ?? Array.Empty<RecommendationAdvice>();
        if (recs.Count > 0)
        {
            headings.AddItem("Recommendations", 1);
            var rt = doc.AddTable(recs.Count + 1, 3, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].Paragraphs[0].Text = "Code";
            rt.Rows[0].Cells[1].Paragraphs[0].Text = "Title";
            rt.Rows[0].Cells[2].Paragraphs[0].Text = "How";
            for (int i = 0; i < recs.Count; i++)
            {
                var rr = recs[i];
                rt.Rows[i + 1].Cells[0].Paragraphs[0].Text = rr.Code ?? string.Empty;
                rt.Rows[i + 1].Cells[1].Paragraphs[0].Text = rr.Title ?? string.Empty;
                rt.Rows[i + 1].Cells[2].Paragraphs[0].Text = rr.How ?? string.Empty;
            }
        }

        // Detailed narrative
        if (nar.Details.Count > 0)
        {
            headings.AddItem("Details", 1);
            foreach (var d in nar.Details) doc.AddParagraph(d);
        }

        // References
        if (nar.References.Count > 0)
        {
            headings.AddItem("References", 1);
            foreach (var r in nar.References) doc.AddParagraph(r);
        }

        doc.Save();
    }
    private static string MechanismMeaning(string type)
    {
        switch (type.ToLowerInvariant())
        {
            case "a": return "Authorize host A/AAAA addresses of the domain (or specified host).";
            case "mx": return "Authorize hosts listed as MX for the domain (or specified).";
            case "ip4": return "Authorize IPv4 address or CIDR block.";
            case "ip6": return "Authorize IPv6 address or CIDR block.";
            case "include": return "Import another domain's SPF policy and evaluate it here.";
            case "exists": return "Authorize based on existence of a DNS record (advanced/expensive).";
            case "ptr": return "Authorize hosts by PTR domain match (discouraged; unreliable).";
            case "redirect": return "Redirect evaluation to another domain's policy (terminal).";
            case "all": return "Catch‑all for remaining senders; qualifier (+/~/‑/?) defines action.";
            case "version": return "SPF version token (v=spf1).";
            default: return "SPF token present.";
        }
    }
}
