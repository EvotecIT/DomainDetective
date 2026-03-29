using System;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Narratives;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderTyposquattingSection(TablerAccordion acc, DomainBucket bucket)
    {
        var info = bucket.Typosquatting;
        if (info == null)
        {
            return;
        }

        var section = SectionProjectors.BuildTyposquatting(info);
        var narrative = TyposquattingNarrative.Build(info.Raw);

        acc.AddItem("Typosquatting", item =>
        {
            item.Icon(TablerIconType.ShieldSearch);
            item.HeaderRight(header =>
            {
                header.Badge(info.ErrorCount > 0 ? $"{info.ErrorCount} Error" + (info.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                header.Badge(info.WarningCount > 0 ? $"{info.WarningCount} Warning" + (info.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                header.Badge(info.Status ?? "Unknown", ColorForStatus(info.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(row =>
                {
                    row.Column(TablerColumnNumber.Twelve, column =>
                    {
                        var findingsCount = info.WarningCount + info.ErrorCount;
                        var findingsBadgeColor = info.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (info.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var references = MergeReferences(section?.References, narrative?.References);

                        RenderExecutionSnapshotCard(column, grid =>
                        {
                            var seen = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(grid, seen, "Status", info.Status ?? "-", PanelColorForStatus(info.Status), light: true);
                            AddGridPanelUnique(grid, seen, "Warnings", info.WarningCount.ToString(), info.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(grid, seen, "Errors", info.ErrorCount.ToString(), info.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (section != null)
                            {
                                AddGridSummaryPanelsUnique(grid, seen, section.Summary);
                            }
                        }, subtitle: "Lookalike candidate generation with reusable DNS evidence per candidate.");

                        RenderGuidanceWizardCard(column, narrative, providerHelp: null, providerHelpTopics: null, references: references);

                        RenderResultsTabsCard(column, tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(r => r.Column(TablerColumnNumber.Twelve, c => RenderSummaryGrid(c, section?.Summary)));
                                panel.Row(r => r.Column(TablerColumnNumber.Twelve, c => RenderSignalsSummary(c, section?.Findings.Select(f => f.Message), section?.Positives)));
                            }).WithIcon(TablerIconType.Cards);

                            tabs.AddTab("Campaigns", panel =>
                            {
                                panel.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
                                {
                                    if (section == null || section.Campaigns.Count == 0)
                                    {
                                        c.Text("No suspicious infrastructure campaigns were identified.").Style(TablerTextStyle.Muted);
                                        RenderReferences(c, references);
                                        return;
                                    }

                                    var rows = section.Campaigns
                                        .Take(100)
                                        .Select(campaign => new
                                        {
                                            campaign.Label,
                                            campaign.Severity,
                                            campaign.CampaignScore,
                                            Domains = campaign.CandidateCount,
                                            Active = campaign.ActiveCount,
                                            Reachable = campaign.ReachableWebCount,
                                            Threat = campaign.ThreatListedCount,
                                            Malicious = campaign.LikelyMaliciousCount,
                                            Impersonation = campaign.LikelyImpersonationCount,
                                            Content = campaign.LikelyImpersonatingCount,
                                            Visual = campaign.LikelyVisualCloneCount,
                                            TopDomain = string.IsNullOrWhiteSpace(campaign.TopCandidateDomain) ? "-" : campaign.TopCandidateDomain,
                                            TopDisposition = string.IsNullOrWhiteSpace(campaign.TopCandidateDisposition) ? "-" : campaign.TopCandidateDisposition,
                                            Actionability = string.IsNullOrWhiteSpace(campaign.Actionability) ? "-" : $"{campaign.Actionability} ({campaign.ActionabilityScore})",
                                            Registrar = string.IsNullOrWhiteSpace(campaign.PrimaryRegistrar) ? "-" : $"{campaign.PrimaryRegistrar} ({campaign.RegistrarConcentrationPercent}%)",
                                            Hosting = string.IsNullOrWhiteSpace(campaign.PrimaryHostingProvider) ? "-" : $"{campaign.PrimaryHostingProvider} ({campaign.HostingConcentrationPercent}%)",
                                            Country = string.IsNullOrWhiteSpace(campaign.PrimaryCountry) ? "-" : $"{campaign.PrimaryCountry} ({campaign.CountryConcentrationPercent}%)",
                                            Abuse = string.IsNullOrWhiteSpace(campaign.PrimaryAbuseContact) ? "-" : campaign.PrimaryAbuseContact,
                                            Pivots = string.IsNullOrWhiteSpace(campaign.PivotSummary) ? "-" : campaign.PivotSummary,
                                            ActionabilitySummary = string.IsNullOrWhiteSpace(campaign.ActionabilitySummary) ? "-" : campaign.ActionabilitySummary,
                                            Action = string.IsNullOrWhiteSpace(campaign.RecommendedAction) ? "-" : campaign.RecommendedAction,
                                            Summary = string.IsNullOrWhiteSpace(campaign.Summary) ? "-" : campaign.Summary
                                        })
                                        .ToList();

                                    c.Card(card =>
                                    {
                                        card.Header(h => h.Title("Hostile campaigns").Icon(TablerIconType.BinaryTree2));
                                        card.Body(body =>
                                        {
                                            var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                            ConfigureStandardDataTable(table);
                                            table.EnablePaging(10, new[] { 10, 25, 50 })
                                                .EnableSearching()
                                                .EnableOrdering();
                                        });
                                    });

                                    RenderReferences(c, references);
                                }));
                            }).WithIcon(TablerIconType.BinaryTree2);

                            var findingsTab = tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(r => r.Column(TablerColumnNumber.Twelve, c => RenderFindings(c, section?.Findings)));
                            }).WithIcon(TablerIconType.AlertTriangle);
                            if (findingsCount > 0)
                            {
                                findingsTab.WithBadge(findingsCount.ToString(), findingsBadgeColor);
                            }

                            tabs.AddTab("Candidates", panel =>
                            {
                                panel.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
                                {
                                    if (section == null || section.Rows.Count == 0)
                                    {
                                        c.Text("No typosquatting candidates generated.").Style(TablerTextStyle.Muted);
                                        RenderReferences(c, references);
                                        return;
                                    }

                                    var rows = section.Rows
                                        .Take(300)
                                        .Select(candidate => new
                                        {
                                            candidate.Domain,
                                            candidate.RiskScore,
                                            candidate.RiskLevel,
                                            Disposition = string.IsNullOrWhiteSpace(candidate.Disposition) ? "-" : candidate.Disposition,
                                            Risk = string.IsNullOrWhiteSpace(candidate.RiskSummary) ? "-" : candidate.RiskSummary,
                                            Cluster = string.IsNullOrWhiteSpace(candidate.InfrastructureClusterLabel) ? "-" : $"{candidate.InfrastructureClusterLabel} ({candidate.InfrastructureClusterSize})",
                                            candidate.Kind,
                                            candidate.EditDistance,
                                            Resolves = candidate.Resolves ? "Yes" : "No",
                                            Registered = candidate.AppearsRegistered ? "Yes" : "No",
                                            A = candidate.ACount,
                                            AAAA = candidate.AaaaCount,
                                            NS = candidate.NsCount,
                                            MX = candidate.MxCount,
                                            Registrar = string.IsNullOrWhiteSpace(candidate.Registrar) ? "-" : candidate.Registrar,
                                            Http = candidate.HttpStatusCode?.ToString() ?? "-",
                                            Threat = candidate.ThreatListed ? "Listed" : "-",
                                            Tech = candidate.TechnologyCount,
                                            IPs = candidate.EnrichedIpCount,
                                            Owned = candidate.LikelyOwned ? $"Likely ({candidate.OwnershipConfidence})" : "-",
                                            Ownership = string.IsNullOrWhiteSpace(candidate.OwnershipSummary) ? "-" : candidate.OwnershipSummary,
                                            External = candidate.LikelyExternal ? $"Likely ({candidate.ExternalConfidence})" : "-",
                                            Distinct = string.IsNullOrWhiteSpace(candidate.ExternalSummary) ? "-" : candidate.ExternalSummary,
                                            Content = candidate.LikelyImpersonating ? $"Likely ({candidate.ContentSimilarityScore})" : (candidate.ContentSimilarityScore > 0 ? candidate.ContentSimilarityScore.ToString() : "-"),
                                            Similarity = string.IsNullOrWhiteSpace(candidate.ContentSimilaritySummary) ? "-" : candidate.ContentSimilaritySummary,
                                            Visual = candidate.LikelyVisualClone ? $"Likely ({candidate.VisualSimilarityScore})" : (candidate.VisualSimilarityScore > 0 ? candidate.VisualSimilarityScore.ToString() : "-"),
                                            VisualType = string.IsNullOrWhiteSpace(candidate.VisualMatchType) ? "-" : candidate.VisualMatchType,
                                            VisualDiff = candidate.VisualSimilarityDistance?.ToString() ?? "-",
                                            VisualSummary = string.IsNullOrWhiteSpace(candidate.VisualSimilaritySummary) ? "-" : candidate.VisualSimilaritySummary,
                                            Enrichment = string.IsNullOrWhiteSpace(candidate.EnrichmentSummary) ? "-" : candidate.EnrichmentSummary
                                        })
                                        .ToList();

                                    c.Card(card =>
                                    {
                                        card.Header(h => h.Title("Generated candidates").Icon(TablerIconType.ListSearch));
                                        card.Body(body =>
                                        {
                                            var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                            ConfigureStandardDataTable(table);
                                            table.EnablePaging(10, new[] { 10, 25, 50 })
                                                .EnableSearching()
                                                .EnableOrdering();
                                        });
                                    });

                                    RenderReferences(c, references);
                                }));
                            }).WithIcon(TablerIconType.Table);
                        });
                    });
                });
            });
        });
    }
}
