using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Builds a single HTML report from mixed view objects using the engine-agnostic composer.
/// </summary>
public static partial class HtmlCompositionReport
{
    /// <summary>
    /// Generates the HTML report.
    /// </summary>
    /// <param name="path">Output file path.</param>
    /// <param name="items">View objects grouped by Subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="openInBrowser">Open the file after saving.</param>
    /// <param name="narrativePlacement">Where to render background narrative (global or per-domain).</param>
    /// <param name="titleOverride">Optional document title override.</param>
    /// <param name="authorOverride">Optional author override.</param>
    /// <param name="descriptionOverride">Optional description/summary override.</param>
    /// <param name="domainOrder">How to order domains in the output (Alphabetical or Input).</param>
    /// <param name="sectionOrderMode">How to order sections within a domain (Canonical, Input, or Custom).</param>
    /// <param name="sectionOrder">Explicit section order used when <paramref name="sectionOrderMode"/> is Custom.</param>
    /// <param name="profile">Presentation profile for HTML (Document or Dashboard).</param>
    /// <param name="themeMode">Theme mode for HTML (Light or Dark).</param>
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
        HtmlProfile profile = HtmlProfile.Document,
        ThemeMode themeMode = ThemeMode.Light)
    {
        if (items == null || items.Count == 0)
        {
            throw new ArgumentException("No items to compose.", nameof(items));
        }

        var grouped = GroupBySubject(items);
        var ordered = domainOrder == DomainOrder.Input
            ? OrderDomainsByInput(items, grouped)
            : grouped.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).ToList();

        var theTitle = string.IsNullOrWhiteSpace(titleOverride)
            ? "Domain Security Compliance Report"
            : titleOverride!;
        var theAuthor = string.IsNullOrWhiteSpace(authorOverride) ? "DomainDetective" : authorOverride;
        var theDesc = string.IsNullOrWhiteSpace(descriptionOverride) ? "Security posture overview for domains" : descriptionOverride;

        var inputSectionOrder = sectionOrderMode == SectionOrderMode.Input
            ? DetermineSectionOrderByDomain(items)
            : new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var normalizedCustom = sectionOrderMode == SectionOrderMode.Custom && sectionOrder != null
            ? NormalizeSectionList(sectionOrder)
            : Array.Empty<string>();

        using var document = new Document
        {
            Head =
            {
                Title = theTitle,
                Author = theAuthor,
                Description = theDesc,
                Revised = DateTime.Now
            },
            LibraryMode = LibraryMode.Online,
            ThemeMode = themeMode
        };

        // Performance: lazy init tables/charts, avoid URL hash navigation for tabs.
        document.Configuration.DataTables.LazyInitByDefault = true;
        document.Configuration.ApexCharts.LazyInitByDefault = true;
        document.Configuration.Tabs.NoHashNavigationByDefault = true;

        document.Body.Page(page =>
        {
            page.Layout = TablerLayout.Combo;

            var execRows = ExecutiveSummaryBuilder.Build(items, domainOrder);
            var overviewLine = OverviewWording.ComposeFromItems(items);

            // Header banner stays above all tabs.
            var headerTitle = theTitle;
            if (grouped.Count > 1)
            {
                try
                {
                    var subjectTitle = BuildSubjectTitle(ordered.Select(kv => kv.Key).ToList());
                    if (!string.IsNullOrWhiteSpace(subjectTitle))
                    {
                        var separators = new[] { " — ", " – ", " - " };
                        foreach (var sep in separators)
                        {
                            var suffix = sep + subjectTitle;
                            if (headerTitle.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                            {
                                headerTitle = headerTitle.Substring(0, headerTitle.Length - suffix.Length).TrimEnd();
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
            try { RenderHeaderBanner(page, headerTitle); } catch { }

            var multiDomain = grouped.Count > 1;
            if (narrativePlacement == NarrativePlacement.Global)
            {
                // Intentionally ignored for HTML dashboards; guidance is rendered per section.
            }

            if (profile == HtmlProfile.Dashboard)
            {
                RenderExecutiveSummary(page, ordered, execRows, overviewLine);
                try { RenderDashboardDiscovery(page, ordered); } catch { }
                try { RenderDashboardSpf(page, ordered); } catch { }
                try { RenderDashboardDmarc(page, ordered); } catch { }
                try { RenderDashboardDkim(page, ordered); } catch { }
                try { RenderDashboardMailTls(page, ordered); } catch { }
                return;
            }

            // Document profile: organize content with top-level tabs (TestimoX-style).
            var totals = (warn: execRows.Sum(r => r.Warnings), err: execRows.Sum(r => r.Errors));
            var grade = ComputeOverallGrade(execRows);
            var gradeBadge = grade switch
            {
                "A" or "B" => TablerBadgeColor.Success,
                "C" => TablerBadgeColor.Warning,
                "D" or "F" => TablerBadgeColor.Danger,
                _ => TablerBadgeColor.Secondary
            };
            var diagnosticsTotal = totals.warn + totals.err;
            var diagnosticsBadge = totals.err > 0
                ? TablerBadgeColor.Danger
                : (totals.warn > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

            page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
            {
                c.Tabs(tabs =>
                {
                    tabs.Settings(s => s.PersistSelection(enable: true, showReset: false, storageKey: "dd:report"));
                    tabs.Navigation(TabNavigation.Fill);

                    tabs.AddTab("Summary", summaryTab =>
                    {
                        RenderExecutiveSummary(summaryTab, ordered, execRows, overviewLine);
                    }).WithIcon(TablerIconType.LayoutDashboard)
                      .WithBadge(grade, gradeBadge);

                    tabs.AddTab("Domains", domainsTab =>
                    {
                        if (multiDomain)
                        {
                            var useTabs = ordered.Count <= 6;
                            if (useTabs)
                            {
                                RenderDomainsTabbed(domainsTab, ordered, sectionOrderMode, normalizedCustom, inputSectionOrder);
                            }
                            else
                            {
                                RenderDomainsAccordion(domainsTab, ordered, sectionOrderMode, normalizedCustom, inputSectionOrder);
                            }
                        }
                        else
                        {
                            foreach (var kv in ordered)
                            {
                                RenderSingleDomain(domainsTab, kv.Key, kv.Value, sectionOrderMode, normalizedCustom, inputSectionOrder);
                            }
                        }
                    }).WithIcon(TablerIconType.World)
                      .WithBadge(ordered.Count.ToString(), TablerBadgeColor.Blue);

                    tabs.AddTab("Diagnostics", diagTab =>
                    {
                        RenderDiagnosticsSection(diagTab, ordered);
                    }).WithIcon(TablerIconType.Activity)
                      .WithBadge(diagnosticsTotal.ToString(), diagnosticsBadge);
                });
            }));
        });

        document.Save(path, openInBrowser);
    }
}
