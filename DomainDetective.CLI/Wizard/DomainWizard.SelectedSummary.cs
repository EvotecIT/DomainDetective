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
                        status = view?.GetType().GetProperty("Status")?.GetValue(view)?.ToString() ?? status;
                        summary = view?.GetType().GetProperty("Summary")?.GetValue(view)?.ToString() ?? summary;
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
}
