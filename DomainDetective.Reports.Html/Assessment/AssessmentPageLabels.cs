using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;

namespace DomainDetective.Reports.Html;

/// <summary>English count forms for the assessment page; whole labels can be translated without suffix rules in the layout.</summary>
internal static class AssessmentPageLabels {
    internal static DisplayLabels Findings() => new DisplayLabels().Map("DMARC_MONITOR_ONLY", "Monitor only");

    internal static string AttentionHeadline(CheckAssessment[] checks) {
        if (checks.Length == 0) return "The collected checks are clear";
        var summaries = checks.Select(check => (check.Summary ?? check.Description ?? (check.Title + " needs review")).Trim().TrimEnd('.')).ToArray();
        string count = checks.Length == 1 ? "One check needs attention" : checks.Length == 2 ? "Two checks need attention" : checks.Length + " checks need attention";
        return count + ": " + string.Join("; ", summaries) + ".";
    }

    internal static string Checks(int count) => Count(count, "{0} check", "{0} checks");
    internal static string Domains(int count) => Count(count, "{0} domain", "{0} domains");
    internal static string Warnings(int count) => Count(count, "{0} warning", "{0} warnings");
    internal static string Errors(int count) => Count(count, "{0} error", "{0} errors");
    private static string Count(int count, string one, string many) => string.Format(CultureInfo.InvariantCulture, count == 1 ? one : many, count);
}
