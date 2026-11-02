using System.Globalization;

namespace DomainDetective.Reports.Html;

/// <summary>English count forms for the assessment page; whole labels can be translated without suffix rules in the layout.</summary>
internal static class AssessmentPageLabels {
    internal static string Checks(int count) => Count(count, "{0} check", "{0} checks");
    internal static string Domains(int count) => Count(count, "{0} domain", "{0} domains");
    internal static string Warnings(int count) => Count(count, "{0} warning", "{0} warnings");
    internal static string Errors(int count) => Count(count, "{0} error", "{0} errors");
    private static string Count(int count, string one, string many) => string.Format(CultureInfo.InvariantCulture, count == 1 ? one : many, count);
}
