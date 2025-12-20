using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Narratives;
using DomainDetective.Views;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: reusable per-check layout helpers (snapshot + guidance).
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderResultsTabsCard(
        TablerColumn c2,
        Action<TablerTabs> buildTabs)
    {
        c2.Card(card =>
        {
            card.Body(body =>
            {
                body.Tabs(tabs =>
                {
                    tabs.Navigation(TabNavigation.Fill);
                    buildTabs(tabs);
                });
            });
        });
    }

    private static void RenderExecutionSnapshotCard(
        TablerColumn c2,
        Action<TablerDataGrid> gridConfig,
        string subtitle = "Key metrics gathered during this check.")
    {
        c2.Card(card =>
        {
            card.Header(h =>
            {
                h.Avatar(a => a.Icon(TablerIconType.Activity).BackgroundColor(TablerColor.Blue).TextColor(TablerColor.White));
                h.Title("Execution Snapshot");
                h.Subtitle(subtitle);
            });
            card.Body(b =>
            {
                b.DataGrid(g =>
                {
                    g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles().MobileResponsive());
                    gridConfig(g);
                    g.AsTiles("16rem");
                });
            });
        });
    }

    private static void RenderGuidanceWizardCard(
        TablerColumn c2,
        NarrativeSections? narrative,
        IReadOnlyList<ProviderHelpLinks>? providerHelp,
        IEnumerable<string>? providerHelpTopics,
        IEnumerable<string>? references)
    {
        var intro = narrative?.Introduction?.Trim();
        var why = narrative?.WhyItMatters?.Trim();
        var investigate = new List<string>();
        if (narrative?.Details != null)
        {
            investigate.AddRange(narrative.Details.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()));
        }
        if (narrative?.Negatives != null)
        {
            investigate.AddRange(narrative.Negatives.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()));
        }
        investigate = investigate.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var fix = narrative?.Remediations?.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList()
            ?? new List<string>();

        var refs = new List<string>();
        if (references != null)
        {
            refs.AddRange(references.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()));
        }
        if (narrative?.References != null)
        {
            refs.AddRange(narrative.References.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()));
        }
        refs = refs.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        bool hasSummary = !string.IsNullOrWhiteSpace(intro);
        bool hasWhy = !string.IsNullOrWhiteSpace(why);
        bool hasInvestigate = investigate.Count > 0;
        bool hasFix = fix.Count > 0;
        bool hasProviderHelp = providerHelp != null && providerHelp.Count > 0;
        bool hasReferences = refs.Count > 0;

        if (!(hasSummary || hasWhy || hasInvestigate || hasFix || hasProviderHelp || hasReferences))
        {
            return;
        }

        c2.Card(card =>
        {
            card.Header(h =>
            {
                h.Avatar(a => a.Icon(TablerIconType.Bulb).BackgroundColor(TablerColor.Yellow).TextColor(TablerColor.White));
                h.Title("Guidance");
                h.Subtitle("Navigate the steps below for context, impact, and remediation.");
            });
            card.Body(body =>
            {
                body.SmartWizard(wizard =>
                {
                    wizard.Settings(s => s
                        .ReportMode()
                        .Theme(SmartWizardTheme.Basic)
                        .Justified(true)
                        .Toolbar(SmartWizardToolbarPosition.None)
                        .ToolbarButtons(false, false)
                        .Navigation(true, true));

                    if (hasSummary)
                    {
                        wizard.AddStep("Summary", TablerIconType.ClipboardText, step =>
                        {
                            step.Text(intro!);
                        });
                    }
                    if (hasWhy)
                    {
                        wizard.AddStep("Why it matters", TablerIconType.InfoCircle, step =>
                        {
                            step.Text(why!);
                        });
                    }
                    if (hasInvestigate)
                    {
                        wizard.AddStep("Investigate", TablerIconType.Search, step =>
                        {
                            var list = step.TablerList();
                            foreach (var t in investigate)
                            {
                                list.AddItem(t, TablerIconType.Search);
                            }
                        });
                    }
                    if (hasFix || hasProviderHelp)
                    {
                        wizard.AddStep("Remediate", TablerIconType.Tool, step =>
                        {
                            if (hasFix)
                            {
                                var list = step.TablerList();
                                foreach (var t in fix)
                                {
                                    list.AddItem(t, TablerIconType.Check);
                                }
                            }

                            if (hasProviderHelp)
                            {
                                step.Row(r => r.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderProviderHelpBadges(col, providerHelp, providerHelpTopics);
                                }));
                            }
                        });
                    }
                    if (hasReferences)
                    {
                        wizard.AddStep("References", TablerIconType.Link, step =>
                        {
                            var rows = refs.Select(u =>
                            {
                                var f = DomainDetective.Reports.LinkFormatter.Format(u);
                                return new { Title = f.Title, Url = f.Url };
                            }).ToList();

                            var t = (TablerTable)step.Table(rows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        });
                    }
                });
            });
        });
    }
}
