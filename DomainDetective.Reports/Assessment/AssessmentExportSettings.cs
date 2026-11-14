using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>Rejects retired presentation settings before assessment exports create files or change defaults.</summary>
public static class AssessmentExportSettings {
    /// <summary>Validates the settings accepted by mixed-view and PowerShell assessment exports.</summary>
    public static void Validate(CompositionExportRequest request) {
        if (request == null) { throw new ArgumentNullException(nameof(request)); }
        var unsupported = new List<string>();
        void Text(string name, string? value) { if (!string.IsNullOrWhiteSpace(value)) { unsupported.Add(name); } }
        Text(nameof(request.Subject), request.Subject);
        Text(nameof(request.Category), request.Category);
        Text(nameof(request.Keywords), request.Keywords);
        Text(nameof(request.Creator), request.Creator);
        Text(nameof(request.CompanyName), request.CompanyName);
        Text(nameof(request.CompanyAddress), request.CompanyAddress);
        Text(nameof(request.CompanyYear), request.CompanyYear);
        Text(nameof(request.LogoPath), request.LogoPath);
        Text(nameof(request.HeaderText), request.HeaderText);
        Text(nameof(request.FooterText), request.FooterText);
        Text(nameof(request.WatermarkText), request.WatermarkText);
        if (request.Scope != ReportScope.Normal) { unsupported.Add(nameof(request.Scope)); }
        if (request.NarrativePlacement != NarrativePlacement.Auto) { unsupported.Add(nameof(request.NarrativePlacement)); }
        // Four was the global default before the layout migration; it remains a neutral default value.
        if (request.SummaryColumnCap.HasValue && request.SummaryColumnCap != 4) { unsupported.Add(nameof(request.SummaryColumnCap)); }
        if (request.HeaderLogoSizePx.HasValue) { unsupported.Add(nameof(request.HeaderLogoSizePx)); }
        if (request.FooterLogoSizePx.HasValue) { unsupported.Add(nameof(request.FooterLogoSizePx)); }
        if (!string.IsNullOrWhiteSpace(request.ExcelProfile) && !string.Equals(request.ExcelProfile, "Workbook", StringComparison.OrdinalIgnoreCase)) {
            unsupported.Add(nameof(request.ExcelProfile));
        }
        // These HTML names are documented aliases for the assessment layout.
        if (!string.IsNullOrWhiteSpace(request.HtmlProfile) && !new[] { "Assessment", "Document", "Dashboard" }.Contains(request.HtmlProfile, StringComparer.OrdinalIgnoreCase)) {
            unsupported.Add(nameof(request.HtmlProfile));
        }
        string theme = (request.HtmlTheme ?? "system").Trim();
        bool hasHtml = request.Formats == null || request.Formats.Count == 0 || request.Formats.Contains(ReportFormat.Html);
        if (!new[] { "system", "light", "dark" }.Contains(theme, StringComparer.OrdinalIgnoreCase)
            || (!hasHtml && !string.Equals(theme, "system", StringComparison.OrdinalIgnoreCase))) {
            unsupported.Add(nameof(request.HtmlTheme));
        }
        if (request.Ordering != null) {
            if (request.Ordering.SectionOrderMode != SectionOrderMode.Canonical) { unsupported.Add("SectionOrderMode"); }
            if (request.Ordering.SectionOrder?.Any(static key => !string.IsNullOrWhiteSpace(key)) == true) { unsupported.Add("SectionOrder"); }
            if (!Enum.IsDefined(typeof(DomainOrder), request.Ordering.DomainOrder)) { unsupported.Add("DomainOrder"); }
        }
        if (request.ProviderHelpOptions != null && !IsDefaultProviderHelp(request.ProviderHelpOptions)) { unsupported.Add(nameof(request.ProviderHelpOptions)); }
        Reject(unsupported);
    }

    /// <summary>Validates general report options before adapting them to the assessment model.</summary>
    public static void Validate(ReportOptions options) {
        if (options == null) { throw new ArgumentNullException(nameof(options)); }
        var unsupported = new List<string>();
        if (!options.IncludeTechnicalDetails) { unsupported.Add(nameof(options.IncludeTechnicalDetails)); }
        if (!options.IncludeRecommendations) { unsupported.Add(nameof(options.IncludeRecommendations)); }
        if (options.IncludeRawData) { unsupported.Add(nameof(options.IncludeRawData)); }
        if (!string.IsNullOrWhiteSpace(options.TemplateName) && options.TemplateName != "Default") { unsupported.Add(nameof(options.TemplateName)); }
        if (options.Theme != ReportTheme.Light) { unsupported.Add(nameof(options.Theme)); }
        if (options.CustomProperties != null) {
            foreach (string key in options.CustomProperties.Keys) {
                if (key != "Domain" && key != "OpenInBrowser") { unsupported.Add("CustomProperties[" + key + "]"); }
            }
        }
        Reject(unsupported);
    }

    private static bool IsDefaultProviderHelp(ProviderHelpRenderOptions options) {
        var defaults = new ProviderHelpRenderOptions();
        return options.ShowUnderMx == defaults.ShowUnderMx && options.ShowUnderSpf == defaults.ShowUnderSpf
            && options.ShowUnderDkim == defaults.ShowUnderDkim && options.ShowUnderDmarc == defaults.ShowUnderDmarc
            && options.ShowUnderBimi == defaults.ShowUnderBimi && options.ShowUnderArc == defaults.ShowUnderArc
            && options.ShowSummaries == defaults.ShowSummaries && options.ShowNotes == defaults.ShowNotes
            && options.ShowBadges == defaults.ShowBadges && options.ShowVerified == defaults.ShowVerified
            && options.IncludeRestricted == defaults.IncludeRestricted && options.IncludeThirdParty == defaults.IncludeThirdParty
            && options.MaxProviders == defaults.MaxProviders && options.TopicOrder != null
            && options.TopicOrder.SequenceEqual(defaults.TopicOrder, StringComparer.OrdinalIgnoreCase);
    }

    private static void Reject(List<string> unsupported) {
        if (unsupported.Count == 0) { return; }
        throw new NotSupportedException("Assessment reports do not support nondefault settings for: "
            + string.Join(", ", unsupported) + ". Remove these overrides or reset export defaults. "
            + "The assessment layout uses fixed detail and section ordering; title, domain order and informational finding visibility remain supported.");
    }
}
