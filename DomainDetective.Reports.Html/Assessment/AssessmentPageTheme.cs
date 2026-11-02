using HtmlForgeX;

namespace DomainDetective.Reports.Html;

/// <summary>A report reading theme, using the shared warm token style and its typography and shape.</summary>
internal static class AssessmentPageTheme {
    internal static PageTheme Create() => new() { Style = HfxThemeStyle.Warm };
}
