using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Aggregates mixed view objects (SPF/DKIM/DMARC) for one or more domains into a single HTML document using the IHtmlComposer adapter.
/// </summary>
/// <summary>
/// Builds a single HTML report from mixed view objects using the engine-agnostic composer.
/// </summary>
public static partial class HtmlCompositionReport {
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
    public static void Generate(string path, IReadOnlyList<object> items, Reports.ReportScope scope, bool openInBrowser = false, Reports.NarrativePlacement narrativePlacement = Reports.NarrativePlacement.Auto, string? titleOverride = null, string? authorOverride = null, string? descriptionOverride = null, DomainDetective.Reports.DomainOrder domainOrder = DomainDetective.Reports.DomainOrder.Alphabetical, DomainDetective.Reports.SectionOrderMode sectionOrderMode = DomainDetective.Reports.SectionOrderMode.Canonical, string[]? sectionOrder = null, HtmlProfile profile = HtmlProfile.Document) {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        var grouped = GroupBySubject(items);
        var ordered = (domainOrder == DomainDetective.Reports.DomainOrder.Input)
            ? OrderDomainsByInput(items, grouped)
            : grouped.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).ToList();

        var title = BuildSubjectTitle(grouped.Keys.ToList());
        var theTitle = string.IsNullOrWhiteSpace(titleOverride) ? $"Domain Security Compliance Report — {title}" : titleOverride;
        var theAuthor = string.IsNullOrWhiteSpace(authorOverride) ? "DomainDetective" : authorOverride;
        var theDesc = string.IsNullOrWhiteSpace(descriptionOverride) ? "Security posture overview for domains" : descriptionOverride;

        var inputSectionOrder = (sectionOrderMode == DomainDetective.Reports.SectionOrderMode.Input)
            ? DetermineSectionOrderByDomain(items)
            : new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var normalizedCustom = (sectionOrderMode == DomainDetective.Reports.SectionOrderMode.Custom && sectionOrder != null)
            ? NormalizeSectionList(sectionOrder)
            : Array.Empty<string>();

        using var document = new Document {
            Head = {
                Title = theTitle,
                Author = theAuthor,
                Description = theDesc,
                Revised = DateTime.Now
            },
            LibraryMode = LibraryMode.Online,
            ThemeMode = ThemeMode.Light
        };

        document.Body.Page(page => {
            page.Layout = TablerLayout.Combo;

            // Executive banner, KPIs, and summary table (built from a single source of truth)
            var execRows = ExecutiveSummaryBuilder.Build(items, domainOrder);
            var overviewLine = OverviewWording.ComposeFromItems(items);
            RenderExecutiveSummary(page, ordered, execRows, overviewLine);

            // Dashboard profile: KPIs/summary plus compact SPF details
            var isDashboard = profile == HtmlProfile.Dashboard;
            if (!isDashboard)
            {
                // Mail Providers — rendered via a dedicated partial to keep file small
                try { RenderProvidersSection(page, ordered); } catch { }
                // MailTLS footnote parity with Word
                try { RenderMailTlsFootnote(page, ordered); } catch { }
                // All References parity with Word
                try { RenderAllReferencesSection(page, items); } catch { }
            }
            else
            {
                try { RenderDashboardSpf(page, ordered); } catch { }
                try { RenderDashboardDmarc(page, ordered); } catch { }
                try { RenderDashboardDkim(page, ordered); } catch { }
                try { RenderDashboardMailTls(page, ordered); } catch { }
            }

            // Optional global background/narrative placeholder (can be enhanced)
            var multiDomain = grouped.Count > 1;
            var placeGlobal = narrativePlacement == Reports.NarrativePlacement.Global || (narrativePlacement == Reports.NarrativePlacement.Auto && multiDomain);
            if (placeGlobal) {
                page.Divider("Background");
                page.Row(rr => rr.Column(TablerColumnNumber.Twelve, cc => {
                    cc.Card(cd => { cd.Body(b => b.Text("Background narrative omitted in this version.")); });
                }));
            }

            // Per-domain overview cards + accordion details (SPF/DMARC/DKIM/MX)

            if (!isDashboard)
            {
                if (multiDomain)
                {
                    RenderDomainsAccordion(page, ordered, sectionOrderMode, normalizedCustom, inputSectionOrder);
                }
                else
                {
                    foreach (var kv in ordered)
                    {
                        RenderSingleDomain(page, kv.Key, kv.Value, sectionOrderMode, normalizedCustom, inputSectionOrder);
                    }
                }
            }
            // Ensure page block closes cleanly
        });

        document.Save(path, openInBrowser);
    }

    }
