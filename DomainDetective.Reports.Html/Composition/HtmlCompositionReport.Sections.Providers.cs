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
    private static void RenderProvidersSection(Element page, List<KeyValuePair<string, DomainBucket>> ordered) {
        var rows = new List<Dictionary<string, object>>();
        var helpByDomain = new List<(string Domain, List<DomainDetective.Views.ProviderHelpTopic> Topics)>();
        foreach (var kv in ordered) {
            var domain = kv.Key;
            var bucket = kv.Value;
            var prov = DomainDetective.Reports.ProviderChainBuilder.Build(bucket.Mx, bucket.Spf);
            var hints = DomainDetective.Reports.ProviderHintsBuilder.Build(bucket.Mx, prov.Primary);
            var hasChain = !string.IsNullOrWhiteSpace(prov.Primary) || prov.Gateways.Count > 0 || prov.Outbound.Count > 0;
            var hintParts = new List<string>();
            if (hints.ConfidencePercent > 0) hintParts.Add($"Confidence {hints.ConfidencePercent}%");
            if (hints.SingleMxOk) hintParts.Add("Single-MX OK");
            if (hints.MinDkimSelectorsToPass > 0) hintParts.Add($"DKIM min {hints.MinDkimSelectorsToPass}");
            if (hints.RecommendedMinMxRecords > 0) hintParts.Add($"Rec MX {hints.RecommendedMinMxRecords}");

            if (!hasChain && hintParts.Count == 0)
            {
                continue;
            }

            rows.Add(new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                ["Domain"] = domain,
                ["Primary"] = string.IsNullOrWhiteSpace(prov.Primary) ? "-" : prov.Primary!,
                ["Gateways"] = prov.Gateways.Count > 0 ? string.Join(", ", prov.Gateways) : "-",
                ["Outbound"] = prov.Outbound.Count > 0 ? string.Join(", ", prov.Outbound) : "-",
                ["Hints"] = hintParts.Count > 0 ? string.Join(" · ", hintParts) : "-"
            });

            try {
                var links = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp;
                if (links != null) {
                    var topics = links.SelectMany(l => l?.Topics ?? new List<DomainDetective.Views.ProviderHelpTopic>())
                                      .Where(t => t != null && !string.IsNullOrWhiteSpace(t.Url))
                                      .ToList();
                    if (topics.Count > 0) helpByDomain.Add((domain, topics!));
                }
            } catch { }
        }

        if (rows.Count == 0 && helpByDomain.Count == 0)
        {
            return;
        }

        page.Divider("Mail Providers");
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("Provider Chain by Domain").Subtitle("Primary · Gateways · Outbound"));
                card.Body(b => {
                    if (rows.Count > 0)
                    {
                        var t = (TablerTable)b.Table(rows, TableType.Tabler);
                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                    }
                    else
                    {
                        b.Text("No provider chain data detected.").Style(TablerTextStyle.Muted);
                    }

                    if (helpByDomain.Count > 0)
                    {
                        b.Divider("Provider Help");
                        foreach (var (domain, topics) in helpByDomain)
                        {
                            b.Text(domain).Style(TablerTextStyle.Muted);
                            b.Row(rr => {
                                rr.Gap(2);
                                foreach (var topic in topics.Take(6))
                                {
                                    string titleSafe = !string.IsNullOrWhiteSpace(topic.Title)
                                        ? topic.Title!
                                        : (!string.IsNullOrWhiteSpace(topic.Topic) ? topic.Topic! : "Help");
                                    rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(titleSafe, TablerBadgeColor.Secondary, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true, href: topic.Url));
                                }
                            });
                        }
                    }

                    b.Divider();
                    b.Text("Legend: Confidence = detection certainty; Single-MX OK = vendor supports single MX; Gateway = inbound security gateway; Outbound = separate sender platform.")
                     .Style(TablerTextStyle.Muted);
                });
            });
        }));
    }
}

