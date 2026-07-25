using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Generates an Excel report using OfficeIMO.Excel: Index, Overview, and per-domain sheet.
/// </summary>
public class ExcelReportGenerator : IReportGenerator {
    public ReportFormat Format => ReportFormat.Excel;

    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Excel;

    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options) {
        var domain = options.CustomProperties?.ContainsKey("Domain") == true
            ? options.CustomProperties["Domain"]?.ToString() ?? "unknown"
            : "unknown";

        var outputPath = options.OutputPath ?? $"{domain}_security_report.xlsx";

        try {
            using var doc = ExcelDocument.Create(outputPath);
            // Document properties
            doc.AsFluent().Info(i => i
                .Title($"Domain Detective — {domain}")
                .Author("DomainDetective")
                .Company("Evotec")
                .Application("OfficeIMO.Excel")
                .Keywords("excel,report,domain,security")
            ).End();

            // Overview sheet (basic KPIs)
            var overview = new SheetComposer(doc, "Overview");
            overview.Title("Domain Detective — Overview", $"Generated {DateTime.Now:yyyy-MM-dd HH:mm}");

            var assessments = healthCheck.GetAllAssessments().ToList();
            int warn = assessments.Count(a => a.Severity == AssessmentSeverity.Warning);
            int err = assessments.Count(a => a.Severity == AssessmentSeverity.Error);
            int info = assessments.Count(a => a.Severity == AssessmentSeverity.Info);

            overview.KpiRow(new (string, object?)[] {
                ("Domain", domain),
                ("Warnings", warn),
                ("Errors", err),
                ("Info", info),
                ("Generated", DateTime.Now.ToString("yyyy-MM-dd"))
            }, perRow: 3);

            overview.Section("At a Glance");
            overview.Columns(2, cols => {
                cols[0].Section("Status Totals").KeyValues(new (string, object?)[] {
                    ("Warnings", warn), ("Errors", err), ("Info", info)
                });
                cols[1].Section("Tips").BulletedList(new []{
                    "Use Index to navigate to domain sheet.",
                    "Filters are enabled on table headers.",
                });
            });

            // Domain sheet with some details
            var s = new SheetComposer(doc, SanitizeSheetName(domain));
            s.Title($"Mail Classification — {domain}", "Summary of key mail signals");

            // Try to build MailClassification view for nicer content
            DomainDetective.Views.MailClassificationInfo? mci = null;
            try {
                var classifier = new MailDomainClassifier(healthCheck, new InternalLogger(false));
                var res = classifier.ClassifyAsync(domain).GetAwaiter().GetResult();
                mci = Views.Converters.Convert(res);
            } catch (Exception ex) {
                Trace.TraceWarning("ExcelReportGenerator: failed to build MailClassification view: {0}", ex.Message);
            }

            s.SectionWithAnchor("Overview")
                .PropertiesGrid(new (string, object?)[] {
                    ("Domain", domain),
                    ("Status", (err > 0) ? "Error" : (warn > 0 ? "Warning" : "OK")),
                    ("Warnings", warn), ("Errors", err)
                }, columns: 2);

            if (mci != null) {
                s.SectionWithAnchor("Signals")
                 .PropertiesGrid(new (string, object?)[] {
                     ("Receiving", string.Join(", ", mci.ReceivingSignals ?? Array.Empty<string>())),
                     ("Sending", string.Join(", ", mci.SendingSignals ?? Array.Empty<string>()))
                 }, columns: 2)
                 .SectionWithAnchor("Score Breakdown");

                // Convert dictionary into rows
                var rows = mci.ScoreBreakdown?.Select(kv => new { Name = kv.Key, Value = kv.Value }).ToList() ?? new();
                s.TableFrom(rows, title: null, configure: o => {
                    o.HeaderCase = HeaderCase.Title;
                }, visuals: v => {
                    v.NumericColumnDecimals["Value"] = 2;
                });
            }

            s.Finish(autoFitColumns: true);

            // Index sheet
            SheetIndex.Add(doc, sheetName: "Index", placeFirst: true, includeNamedRanges: false);
            SheetIndex.AddBackLinks(doc, tocSheetName: "Index", row: 2, col: 1, text: "← Index");

            var errors = doc.ValidateOpenXml();
            if (errors.Count > 0) {
                // Non-blocking; record in metadata
            }

            doc.Save();
            return Task.FromResult(new ReportResult {
                Success = true,
                FilePath = outputPath,
                Format = ReportFormat.Excel
            });
        } catch (Exception ex) {
            return Task.FromResult(new ReportResult {
                Success = false,
                FilePath = outputPath,
                Format = ReportFormat.Excel,
                ErrorMessage = ex.Message
            });
        }
    }

    private static string SanitizeSheetName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "Sheet";
        var invalid = new char[] { ':', '\\', '/', '?', '*', '[', ']' };
        var cleaned = new string(name.Where(ch => !invalid.Contains(ch)).ToArray());
        if (cleaned.Length > 31) cleaned = cleaned.Substring(0, 31);
        if (string.IsNullOrWhiteSpace(cleaned)) cleaned = "Sheet";
        return cleaned;
    }
}
