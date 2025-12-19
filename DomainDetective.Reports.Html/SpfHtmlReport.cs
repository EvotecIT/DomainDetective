using System;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

public static class SpfHtmlReport
{
    public static void Generate(string path, DomainDetective.SpfAnalysis spf, string domain, bool openInBrowser)
    {
        using var document = new Document
        {
            Head =
            {
                Title = $"SPF Report - {domain}",
                Author = "DomainDetective",
                Revised = DateTime.Now,
                Description = $"SPF analysis for {domain}"
            },
            LibraryMode = LibraryMode.Online,
            ThemeMode = ThemeMode.Light
        };

        document.Body.Page(page =>
        {
            page.Layout = TablerLayout.Fluid;

            page.Row(row =>
            {
                row.Column(TablerColumnNumber.Twelve, col =>
                {
                    col.H1($"SPF Report for {domain}");
                    col.Text($"Generated on {DateTime.Now:yyyy-MM-dd HH:mm:ss}").Style(TablerTextStyle.Muted);
                });
            });

            // Introduction
            var nar = DomainDetective.Narratives.SpfNarrative.Build(spf);
            page.Divider("Introduction");
            page.Row(r => {
                r.Column(TablerColumnNumber.Twelve, col => {
                    col.Text(nar.Introduction);
                });
            });
            page.Divider("Why this matters");
            page.Row(r => {
                r.Column(TablerColumnNumber.Twelve, col => {
                    col.Text(nar.WhyItMatters);
                });
            });

            // Summary cards
            page.Divider("Summary");
            page.Row(row =>
            {
                InfoCard(row, "Record Present", spf.SpfRecordExists ? "Yes" : "No", spf.SpfRecordExists ? "#10B981" : "#EF4444");
                InfoCard(row, "Starts Correctly", spf.StartsCorrectly ? "Yes" : "No", spf.StartsCorrectly ? "#10B981" : "#F59E0B");
                InfoCard(row, "DNS Lookups", spf.DnsLookupsCount.ToString(), spf.ExceedsDnsLookups ? "#EF4444" : "#3B82F6");
                InfoCard(row, "Multiple 'all'", spf.MultipleAllMechanisms ? "Yes" : "No", spf.MultipleAllMechanisms ? "#EF4444" : "#3B82F6");
            });

            // Provider summary
            var providers = spf.SpfPartAnalyses?.Where(p => !string.IsNullOrWhiteSpace(p.Provider))
                .GroupBy(p => p.Provider!)
                .Select(g => $"{g.Key} ({g.Count()})").ToList() ?? new System.Collections.Generic.List<string>();
            if (providers.Count > 0)
            {
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        col.Card(card => {
                            card.Header(h => h.Title("Provider Summary"));
                            card.Body(b => b.Text(string.Join(", ", providers)).Style(TablerTextStyle.Muted));
                        });
                    });
                });
            }

            // Highlights
            if (nar.Highlights.Count > 0)
            {
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        col.Card(card => {
                            card.Header(h => h.Title("Highlights"));
                            card.Body(b => b.AddList(list => list.WithItems(items => { foreach (var v in nar.Highlights) items.Item(v); })));
                        });
                    });
                });
            }

            // Findings
            page.Divider("Findings");
            var assessments = spf.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
            page.Row(r =>
            {
                r.Column(TablerColumnNumber.Twelve, col =>
                {
                    col.Card(card =>
                    {
                        card.Header(h => h.Title("Assessments"));
                        card.Body(body =>
                        {
                            // Include Info-level findings by default to show positives (can be toggled at callsite later if needed)
                            var showInfo = true;
                            var rows = (showInfo ? assessments : assessments.Where(a => a.Severity != AssessmentSeverity.Info)).Select(a => new
                            {
                                Severity = a.Severity.ToString(),
                                Code = a.Code,
                                Target = a.Target,
                                Message = a.Message
                            });
                            var table = (TablerTable)body.Table(rows, TableType.Tabler);
                            table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        });
                    });
                });
            });

            // Mechanisms
            page.Divider("Mechanisms");
            var parts = spf.SpfPartAnalyses?.ToList() ?? new System.Collections.Generic.List<DomainDetective.SpfPartAnalysis>();
            if (parts.Count > 0)
            {
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        col.Card(card => {
                            card.Header(h => h.Title("Mechanism Breakdown"));
                            card.Body(b => {
                                var table = (TablerTable)b.Table(parts.Select(p => new {
                                    Qualifier = string.IsNullOrEmpty(p.Prefix) ? "+" : p.Prefix,
                                    Type = p.Type,
                                    Value = p.Value,
                                    Provider = p.Provider
                                }), TableType.Tabler);
                                table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            });
                        });
                    });
                });

                // Explainer
                var types = parts.Select(p => p.Type).Where(t => !string.IsNullOrWhiteSpace(t)).Distinct(System.StringComparer.OrdinalIgnoreCase).ToList();
                if (types.Count > 0)
                {
                    page.Row(r => {
                        r.Column(TablerColumnNumber.Twelve, col => {
                            col.Card(card => {
                                card.Header(h => h.Title("Mechanism Explainer"));
                                card.Body(b => {
                                    var table = (TablerTable)b.Table(types.Select(t => new { Type = t, Meaning = MechanismMeaning(t!) }), TableType.Tabler);
                                    table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                });
                            });
                        });
                    });
                    page.Row(r => {
                        r.Column(TablerColumnNumber.Twelve, col => {
                            col.Card(card => {
                                card.Header(h => h.Title("Qualifier Legend"));
                                card.Body(b => b.AddList(list => list.WithItems(items => {
                                    items.Item("+ (pass): explicitly allow");
                                    items.Item("- (fail): explicitly deny");
                                    items.Item("~ (softfail): likely deny, often accepted but marked");
                                    items.Item("? (neutral): no assertion");
                                })));
                            });
                        });
                    });
                }
            }

            // Evidence
            page.Divider("Evidence");
            page.Row(r =>
            {
                r.Column(TablerColumnNumber.Six, col =>
                {
                    col.Card(card =>
                    {
                        card.Header(h => h.Title("SPF Record"));
                        card.Body(b =>
                        {
                            b.Text(spf.SpfRecord ?? string.Empty);
                            b.DataGrid(grid =>
                            {
                                grid.AddItem("Multiple Records", spf.MultipleSpfRecords ? "Yes" : "No");
                                grid.AddItem("All Mechanism", spf.AllMechanism ?? "");
                                grid.AddItem("Redirect", spf.RedirectValue ?? "");
                                grid.AddItem("exp", spf.ExpValue ?? "");
                            });
                        });
                    });
                });
                r.Column(TablerColumnNumber.Six, col =>
                {
                    col.Card(card =>
                    {
                        card.Header(h => h.Title("Mechanisms"));
                        card.Body(b =>
                        {
                            var mech = new[]
                            {
                                ("A", spf.ARecords),
                                ("MX", spf.MxRecords),
                                ("IPv4", spf.Ipv4Records),
                                ("IPv6", spf.Ipv6Records),
                                ("Include", spf.IncludeRecords),
                                ("Exists", spf.ExistsRecords),
                                ("PTR", spf.PtrRecords)
                            };
                            foreach (var (name, list) in mech)
                            {
                                if (list == null || list.Count == 0) continue;
                                b.H5(name);
                                b.AddList(lst => lst.WithItems(items => { foreach (var v in list.Distinct()) items.Item(v); }));
                            }
                        });
                    });
                });
            });

            // Lookups
            if (spf.DnsLookups != null && spf.DnsLookups.Count > 0)
            {
                page.Divider("DNS Lookups");
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        col.Card(card => {
                            card.Header(h => h.Title("Lookups"));
                            card.Body(b => b.AddList(list => list.WithItems(items => { foreach (var v in spf.DnsLookups.Distinct()) items.Item(v); })));
                        });
                    });
                });
            }

            // Flattened IP Analysis
            var flat = spf.FlattenedIpAnalysis;
            page.Divider("Flattened IP Analysis");
            page.Row(r => {
                r.Column(TablerColumnNumber.Twelve, col => {
                    col.Card(card => {
                        card.Header(h => h.Title("Summary"));
                        card.Body(b => b.DataGrid(grid => {
                            grid.AddItem("Unique IPs", (flat?.UniqueIps?.Count ?? 0).ToString());
                            grid.AddItem("Duplicate IPs", (flat?.DuplicateIps?.Count ?? 0).ToString());
                            grid.AddItem("Tokens Resolved", (flat?.TokenIpMap?.Count ?? 0).ToString());
                        }));
                    });
                });
            });
            if (flat?.TokenIpMap != null && flat.TokenIpMap.Count > 0)
            {
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        col.Card(card => {
                            card.Header(h => h.Title("Token → IPs (counts)"));
                            card.Body(b => {
                                var table = (TablerTable)b.Table(flat.TokenIpMap.Select(kv => new { Token = kv.Key, Count = kv.Value?.Count ?? 0 }), TableType.Tabler);
                                table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            });
                        });
                    });
                });
                var sample = flat.UniqueIps?.Take(20).ToList() ?? new System.Collections.Generic.List<string>();
                if (sample.Count > 0)
                {
                    page.Row(r => {
                        r.Column(TablerColumnNumber.Twelve, col => {
                            col.Card(card => {
                                card.Header(h => h.Title("Sample Unique IPs"));
                                card.Body(b => b.AddList(list => list.WithItems(items => { foreach (var ip in sample) items.Item(ip); })));
                            });
                        });
                    });
                }
            }

            // Policy Checks
            page.Divider("Policy Checks");
            page.Row(r => {
                r.Column(TablerColumnNumber.Twelve, col => {
                    col.Card(card => {
                        card.Header(h => h.Title("Checks"));
                        card.Body(b => b.DataGrid(grid => {
                            grid.AddItem("Cycle Detected", spf.CycleDetected ? "Yes" : "No");
                            grid.AddItem("Cycle Path", spf.CyclePath ?? "");
                            grid.AddItem("Advisory", spf.Advisory ?? "");
                        }));
                    });
                });
            });

            // Details narrative
            if (nar.Details.Count > 0)
            {
                page.Divider("Details");
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        foreach (var d in nar.Details) col.Text(d);
                    });
                });
            }

            // Recommendations
            if (spf.Recommendations != null && spf.Recommendations.Count > 0)
            {
                page.Divider("Recommendations");
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        col.Card(card => {
                            card.Header(h => h.Title("Recommended Actions"));
                            card.Body(b => {
                                var table = (TablerTable)b.Table(spf.Recommendations.Select(x => new { x.Code, x.Title, x.How }), TableType.Tabler);
                                table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            });
                        });
                    });
                });
            }

            // References
            if (nar.References.Count > 0)
            {
                page.Divider("References");
                page.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, col => {
                        col.Card(card => {
                            card.Header(h => h.Title("References"));
                            card.Body(b => {
                                b.Row(rr => {
                                    rr.Gap(2);
                                    foreach (var url in nar.References)
                                    {
                                        var f = DomainDetective.Reports.LinkFormatter.Format(url);
                                        rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url));
                                    }
                                });
                            });
                        });
                    });
                });
            }
        });

        document.Save(path, openInBrowser);
    }

    private static void InfoCard(TablerRow row, string title, string value, string color)
    {
        row.Column(TablerColumnNumber.Three, col =>
        {
            col.Card(card =>
            {
                card.Background(color, "#FFFFFF")
                    .Header(h => h.Title(title))
                    .Body(b => b.H2(value));
            });
        });
    }

    private static string MechanismMeaning(string type)
    {
        switch (type?.ToLowerInvariant())
        {
            case "a": return "Authorize host A/AAAA addresses of the domain (or specified host).";
            case "mx": return "Authorize hosts listed as MX for the domain (or specified).";
            case "ip4": return "Authorize IPv4 address or CIDR block.";
            case "ip6": return "Authorize IPv6 address or CIDR block.";
            case "include": return "Import another domain's SPF policy and evaluate it here.";
            case "exists": return "Authorize based on existence of a DNS record (advanced/expensive).";
            case "ptr": return "Authorize hosts by PTR domain match (discouraged; unreliable).";
            case "redirect": return "Redirect evaluation to another domain's policy (terminal).";
            case "all": return "Catch‑all for remaining senders; qualifier (+/~/‑/?) defines action.";
            case "version": return "SPF version token (v=spf1).";
            default: return "SPF token present.";
        }
    }
}


