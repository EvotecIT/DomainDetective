using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport {
    private static void BuildOverviewSheet(ExcelDocument doc, IReadOnlyList<object> items, DomainOrder order, List<KeyValuePair<string, DomainBucket>> domains) {
        var overview = new SheetComposer(doc, "Overview");
        overview.Title("Security Overview", $"Generated {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC");
        var rows = ExecutiveSummaryBuilder.Build(items, order);
        var warnings = rows.Sum(row => row.Warnings);
        var errors = rows.Sum(row => row.Errors);
        overview.KpiRow(new (string, object?)[] { ("Domains", domains.Count), ("Errors", errors), ("Warnings", warnings) }, perRow: 3);
        ExcelReportLayout.Section(overview, "Assessment brief");
        ExcelReportLayout.Paragraph(overview, errors + " error(s) and " + warnings + " warning(s) appear in the supplied assessment views. Start with the action plan, then follow the findings to the domain evidence. Unperformed checks remain unknown.");
        ExcelReportLayout.Paragraph(overview, OverviewWording.ComposeFromItems(items).Replace("The table highlights", "Supporting sheets show"));
        ExcelReportLayout.Section(overview, "Domains and priorities");
        foreach (var row in rows) {
            ExcelReportLayout.Section(overview, MessageHeaderReport.VisibleText(row.Domain));
            ExcelReportLayout.Paragraph(overview, row.Errors + " error(s), " + row.Warnings + " warning(s). MX: " + row.Mx + "; SPF: " + row.Spf + "; DKIM: " + row.Dkim + "; DMARC: " + row.Dmarc + ".");
            ExcelReportLayout.Paragraph(overview, "Microsoft 365: " + row.Microsoft365 + "; workloads: " + row.Microsoft365Workloads + ".");
            if (domains.FirstOrDefault(pair => string.Equals(pair.Key, row.Domain, StringComparison.OrdinalIgnoreCase)).Value is DomainBucket bucket) {
                var chain = ProviderChainBuilder.Build(bucket.Mx, bucket.Spf);
                ExcelReportLayout.Paragraph(overview, "Mail provider evidence: " + (string.IsNullOrWhiteSpace(chain.Primary) ? "unknown" : MessageHeaderReport.VisibleText(chain.Primary)) + ".");
            }
        }
        ExcelReportLayout.Section(overview, "Report navigation");
        ExcelReportLayout.Paragraph(overview, "Index links to every sheet. Recommendations explains why to act, what to change and how to verify. Findings retains assessment messages and codes. Matrix and Summary compare control status; domain sheets contain supporting records.");
        for (var column = 1; column <= 6; column++) { overview.Sheet.SetColumnWidth(column, 18); }
        overview.Sheet.MergeRange("A1:F1");
        overview.Sheet.MergeRange("A2:F2");
        overview.Sheet.CellFontSize(1, 1, 20);
        overview.Sheet.SetRowHeight(1, 36);
        overview.Sheet.SetRowHeight(2, 25);
        overview.Sheet.Freeze(topRows: 3);
        overview.Finish(autoFitColumns: false);
    }
}
