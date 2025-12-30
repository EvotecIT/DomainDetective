using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class DmarcAggregateWordSectionWriter
{
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Views.DmarcAggregateTimeSeriesInfo aggregate,
        string domain,
        ReportScope scope,
        bool showInfoFindings,
        bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (aggregate == null) throw new ArgumentNullException(nameof(aggregate));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.DmarcAggregateNarrative.Build(domain);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DMARC aggregate report rollups and trends based on ingested RUA reports.");

        var rows = new List<(string Key, string Value)>
        {
            ("Period Start (UTC)", aggregate.PeriodStartUtc?.UtcDateTime.ToString("u") ?? "-"),
            ("Period End (UTC)", aggregate.PeriodEndUtc?.UtcDateTime.ToString("u") ?? "-"),
            ("Reports", aggregate.SnapshotCount.ToString()),
            ("Total Messages", aggregate.TotalCount.ToString()),
            ("Pass", aggregate.TotalCount > 0 ? $"{aggregate.PassCount} ({aggregate.PassRatePercent:0.0}%)" : aggregate.PassCount.ToString()),
            ("Fail", aggregate.FailCount.ToString()),
            ("Status", aggregate.Status ?? "-")
        };

        if (aggregate.DispositionCounts != null && aggregate.DispositionCounts.Count > 0)
        {
            var top = aggregate.DispositionCounts
                .OrderByDescending(kv => kv.Value)
                .Take(5)
                .Select(kv => $"{kv.Key}={kv.Value}");
            rows.Add(("Disposition (top)", string.Join(", ", top)));
        }

        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Key);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Value);
        }

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (aggregate.Positives != null && aggregate.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("Positive posture signals observed in the ingested aggregate reports:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in aggregate.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = (aggregate.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
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
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message ?? string.Empty);
            }
        }

        // Evidence / trends
        if (scope == ReportScope.Detailed)
        {
            if (aggregate.Daily != null && aggregate.Daily.Count > 0)
            {
                headings.AddItem("Trends", baseLevel);
                doc.AddParagraph("Daily rollups over the reporting period (capped).");
                const int maxRows = 31;
                var daily = aggregate.Daily
                    .OrderBy(x => x.DateUtc)
                    .ToList();
                if (daily.Count > maxRows)
                {
                    daily = daily.Skip(daily.Count - maxRows).ToList();
                }
                var dt = doc.AddTable(daily.Count + 1, 5, WordTableStyle.TableGrid);
                dt.Rows[0].Cells[0].AddParagraph("Date (UTC)");
                dt.Rows[0].Cells[1].AddParagraph("Total");
                dt.Rows[0].Cells[2].AddParagraph("Pass");
                dt.Rows[0].Cells[3].AddParagraph("Fail");
                dt.Rows[0].Cells[4].AddParagraph("Pass %");
                for (int i = 0; i < daily.Count; i++)
                {
                    var d = daily[i];
                    dt.Rows[i + 1].Cells[0].AddParagraph(d.DateUtc.ToString("yyyy-MM-dd"));
                    dt.Rows[i + 1].Cells[1].AddParagraph(d.TotalCount.ToString());
                    dt.Rows[i + 1].Cells[2].AddParagraph(d.PassCount.ToString());
                    dt.Rows[i + 1].Cells[3].AddParagraph(d.FailCount.ToString());
                    dt.Rows[i + 1].Cells[4].AddParagraph(d.PassRatePercent.ToString("0.0"));
                }
            }

            WriteTopList(doc, headings, baseLevel, "Top failing source IPs", aggregate.TopFailingSourceIps);
            WriteTopList(doc, headings, baseLevel, "Top failing header-from", aggregate.TopFailingHeaderFrom);
            WriteTopList(doc, headings, baseLevel, "Top failing DKIM domains", aggregate.TopFailingDkimDomains);
            WriteTopList(doc, headings, baseLevel, "Top failing SPF domains", aggregate.TopFailingSpfDomains);
        }

        // References
        if (aggregate.References != null && aggregate.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, aggregate.References);
        }
    }

    private static void WriteTopList(WordDocument doc, WordList headings, int baseLevel, string title, IReadOnlyList<DomainDetective.Views.NamedCount>? items)
    {
        if (items == null || items.Count == 0) return;
        headings.AddItem(title, baseLevel);
        var t = doc.AddTable(items.Count + 1, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Key");
        t.Rows[0].Cells[1].AddParagraph("Count");
        for (int i = 0; i < items.Count; i++)
        {
            var r = items[i];
            t.Rows[i + 1].Cells[0].AddParagraph(r.Key ?? string.Empty);
            t.Rows[i + 1].Cells[1].AddParagraph(r.Count.ToString());
        }
    }
}
