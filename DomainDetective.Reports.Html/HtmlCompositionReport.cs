using System;
using System.Collections.Generic;
using HtmlForgeX;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Builds a single HTML report from mixed view objects. Every profile renders the scored assessment report
/// (<see cref="AssessmentHtmlReport"/>); the earlier Document and Dashboard layouts were retired.
/// </summary>
public static partial class HtmlCompositionReport
{
    /// <summary>
    /// Generates the HTML report.
    /// </summary>
    /// <param name="path">Output file path.</param>
    /// <param name="items">View objects grouped by Subject.</param>
    /// <param name="scope">Detail level. Kept for compatibility; the assessment report always shows every check.</param>
    /// <param name="openInBrowser">Open the file after saving.</param>
    /// <param name="narrativePlacement">Kept for compatibility; the assessment report places guidance per check.</param>
    /// <param name="titleOverride">Optional document title override.</param>
    /// <param name="authorOverride">Kept for compatibility.</param>
    /// <param name="descriptionOverride">Kept for compatibility.</param>
    /// <param name="domainOrder">How to order domains in the output (Alphabetical or Input).</param>
    /// <param name="sectionOrderMode">Kept for compatibility; checks follow the area and chapter order.</param>
    /// <param name="sectionOrder">Kept for compatibility.</param>
    /// <param name="profile">Kept for compatibility; every profile renders the assessment report.</param>
    /// <param name="themeMode">Initial theme.</param>
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        bool openInBrowser = false,
        NarrativePlacement narrativePlacement = NarrativePlacement.Auto,
        string? titleOverride = null,
        string? authorOverride = null,
        string? descriptionOverride = null,
        DomainOrder domainOrder = DomainOrder.Alphabetical,
        SectionOrderMode sectionOrderMode = SectionOrderMode.Canonical,
        string[]? sectionOrder = null,
        HtmlProfile profile = HtmlProfile.Assessment,
        ThemeMode themeMode = ThemeMode.System)
        => Generate(path, items, scope, openInBrowser, narrativePlacement, titleOverride, authorOverride,
            descriptionOverride, domainOrder, sectionOrderMode, sectionOrder, profile, themeMode, false);

    /// <summary>Generates HTML with explicit informational finding visibility.</summary>
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        bool openInBrowser,
        NarrativePlacement narrativePlacement,
        string? titleOverride,
        string? authorOverride,
        string? descriptionOverride,
        DomainOrder domainOrder,
        SectionOrderMode sectionOrderMode,
        string[]? sectionOrder,
        HtmlProfile profile,
        ThemeMode themeMode,
        bool showInfoFindings)
    {
        if (items == null || items.Count == 0)
        {
            throw new ArgumentException("No items to compose.", nameof(items));
        }

        AssessmentHtmlReport.Generate(
            path,
            items,
            new DomainAssessmentOptions { Title = titleOverride, DomainOrder = domainOrder },
            new AssessmentHtmlOptions { Theme = themeMode, ShowInfoFindings = showInfoFindings },
            openInBrowser);
    }
}
