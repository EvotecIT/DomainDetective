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
                        var primary = bucket.Mx?.ProviderPrimary ?? string.Empty;
                        var gateways = bucket.Mx?.ProviderGateways ?? new List<string>();
                        var outbound = new List<string>();
                        try {
                            var names = (bucket.Spf?.ProviderHelp ?? new List<DomainDetective.Views.ProviderHelpLinks>())
                                .Select(p => p?.ProviderName)
                                .Where(n => !string.IsNullOrWhiteSpace(n))
                                .Distinct(StringComparer.OrdinalIgnoreCase)
                                .ToList();
                            foreach (var n in names) {
                                if (string.IsNullOrWhiteSpace(n)) continue;
                                if (string.Equals(n, primary, StringComparison.OrdinalIgnoreCase)) continue;
                                if (gateways.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
                                outbound.Add(n);
                            }
                        } catch { }

                        var chainParts = new List<string>();
                        if (!string.IsNullOrWhiteSpace(primary)) chainParts.Add($"Primary: {primary}");
                        if (gateways.Count > 0) chainParts.Add($"Gateways: {string.Join(", ", gateways)}");
                        if (outbound.Count > 0) chainParts.Add($"Outbound: {string.Join(", ", outbound)}");
                        var chain = chainParts.Count > 0 ? string.Join("; ", chainParts) : "(no provider detected)";

                        b.Row(rr => {
                            rr.Gap(2);
                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(domain, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                            rr.Column(TablerColumnNumber.Auto, cc => cc.Text(chain));
                        });

                        // Quick links for primary provider
                        try {
                            var links = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp;
                            var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, primary, StringComparison.OrdinalIgnoreCase))
                                              ?? links?.FirstOrDefault();
                            if (primaryHelp != null && (primaryHelp.Topics?.Count ?? 0) > 0) {
                                var top = primaryHelp.Topics.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
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
                });
            });
        }));
    }
}
