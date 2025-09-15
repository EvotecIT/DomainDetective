using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: provider chain/links section.
/// </summary>
public static partial class HtmlCompositionReport {
    private static void RenderProvidersSection(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered) {
        page.Divider("Mail Providers");
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("Provider Chain by Domain").Subtitle("Primary · Gateways · Outbound"));
                card.Body(b => {
                    foreach (var kv in ordered) {
                        var domain = kv.Key; var bucket = kv.Value;
                        var prov = DomainDetective.Reports.ProviderChainBuilder.Build(bucket.Mx, bucket.Spf);
                        var chainParts = new List<string>();
                        if (!string.IsNullOrWhiteSpace(prov.Primary)) chainParts.Add($"Primary: {prov.Primary}");
                        if (prov.Gateways.Count > 0) chainParts.Add($"Gateways: {string.Join(", ", prov.Gateways)}");
                        if (prov.Outbound.Count > 0) chainParts.Add($"Outbound: {string.Join(", ", prov.Outbound)}");
                        var chainText = chainParts.Count > 0 ? string.Join("; ", chainParts) : "(no provider detected)";

                        b.Row(rr => {
                            rr.Gap(2);
                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(domain, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                            rr.Column(TablerColumnNumber.Auto, cc => cc.Text(chainText));
                        });

                        // Badges/hints (Word parity)
                        try {
                            var hints = DomainDetective.Reports.ProviderHintsBuilder.Build(bucket.Mx, prov.Primary);
                            b.Row(rr => {
                                rr.Gap(2);
                                if (hints.ConfidencePercent > 0)
                                    rr.Column(TablerColumnNumber.Auto, cc => cc.Badge($"Confidence {hints.ConfidencePercent}%", TablerBadgeColor.Info, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                if (hints.SingleMxOk)
                                    rr.Column(TablerColumnNumber.Auto, cc => cc.Badge("Single-MX OK", TablerBadgeColor.Success, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                if (prov.Gateways.Count > 0)
                                    rr.Column(TablerColumnNumber.Auto, cc => cc.Badge("Gateway", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                if (prov.Outbound.Count > 0)
                                    rr.Column(TablerColumnNumber.Auto, cc => cc.Badge("Outbound", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                            });
                        } catch { }

                        // Quick links for primary provider
                        try {
                            var links = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp;
                            var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, prov.Primary, StringComparison.OrdinalIgnoreCase))
                                              ?? links?.FirstOrDefault();
                            if (primaryHelp != null && (primaryHelp.Topics?.Count ?? 0) > 0) {
                                var topics = primaryHelp.Topics ?? new List<DomainDetective.Views.ProviderHelpTopic>();
                                var top = topics.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
                                if (top.Count > 0) {
                                    b.Row(rr => {
                                        rr.Gap(2);
                                        foreach (var t in top) {
                                            var titleSafe = string.IsNullOrWhiteSpace(t?.Title) ? t!.Topic : t!.Title;
                                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(titleSafe!, TablerBadgeColor.Secondary, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: t!.Url));
                                        }
                                    });
                                }
                            }
                        } catch { }

                        b.Divider();
                    }
                    // Legend explaining badges and hints (parity with Word)
                    try {
                        b.Text("Legend: Confidence = detection certainty; Single‑MX OK = vendor supports single MX; Gateway = inbound security gateway; Outbound = separate sender platform.")
                         .Style(TablerTextStyle.Muted);
                    } catch { }
                });
            });
        }));
    }
}
