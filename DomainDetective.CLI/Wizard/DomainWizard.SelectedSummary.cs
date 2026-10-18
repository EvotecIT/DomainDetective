using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using DomainDetective.Views;
using Spectre.Console;

namespace DomainDetective.CLI.Wizard;

public sealed partial class DomainWizard {
    private static void RenderSelectedSummary(DomainHealthCheck health, HealthCheckType[] checks, ISet<HealthCheckType> completed) {
        var analyses = health.GetAnalysisMap();
        var table = new Table().Border(TableBorder.Rounded).AddColumn("Check").AddColumn("Status").AddColumn("Key findings");
        foreach (var check in checks) {
            if (!completed.Contains(check)) {
                table.AddRow(check.ToString(), "Incomplete", "Collected evidence may be partial.");
                continue;
            }
            analyses.TryGetValue(check, out var analysis);
            var status = "Collected";
            var summary = "See check details for collected evidence.";
            if (analysis != null) {
                // Adapt existing typed core views instead of duplicating their status policy.
                var converter = typeof(Converters).GetMethod("Convert", new[] { analysis.GetType() });
                if (converter != null) {
                    try {
                        var view = converter.Invoke(null, new[] { analysis });
                        if (view is System.Collections.IEnumerable items && view is not string) {
                            var rows = items.Cast<object>().Select(item => (
                                Status: ViewValue(item, "Status") ?? "Collected",
                                Summary: string.Join(": ", new[] { ViewValue(item, "Selector"), ViewValue(item, "Summary") }
                                    .Where(value => !string.IsNullOrWhiteSpace(value))))).ToArray();
                            status = rows.Any(row => row.Status == "Error") ? "Error"
                                : rows.Any(row => row.Status == "Warning") ? "Warning"
                                : rows.Length > 0 && rows.All(row => row.Status == "OK") ? "OK" : "Collected";
                            summary = rows.Length == 0 ? "No selector results." : string.Join("; ", rows.Select(row => row.Summary));
                        } else {
                            status = ViewValue(view, "Status") ?? status;
                            summary = ViewValue(view, "Summary") ?? summary;
                        }
                    } catch (TargetInvocationException) {
                        status = "Summary unavailable";
                    }
                } else if (analysis is IHasAssessments assessed) {
                    int errors = assessed.Assessments.Count(item => item.Severity == AssessmentSeverity.Error);
                    int warnings = assessed.Assessments.Count(item => item.Severity == AssessmentSeverity.Warning);
                    status = errors > 0 ? "Error" : warnings > 0 ? "Warning" : "Collected";
                    summary = $"{errors} errors, {warnings} warnings";
                }
            }
            table.AddRow(check.ToString(), status.EscapeMarkup(), summary.EscapeMarkup());
        }
        AnsiConsole.Write(table);
    }

    private static string? ViewValue(object? view, string property) =>
        view?.GetType().GetProperty(property)?.GetValue(view)?.ToString();
}
