using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: discovery/inventory overview for Dashboard profile.
/// </summary>
public static partial class HtmlCompositionReport
{
    private sealed class DiscoveryOverviewRow
    {
        public string Domain { get; set; } = string.Empty;
        public int Subdomains { get; set; }
        public int CtUniqueCerts { get; set; }
        public int CtIssued7d { get; set; }
        public int CtIssued30d { get; set; }
        public string DnsProvider { get; set; } = "-";
        public string MailProvider { get; set; } = "-";
        public string Microsoft365 { get; set; } = "-";
        public string M365Confidence { get; set; } = "-";
        public int M365Services { get; set; }
        public string M365WorkloadEvidence { get; set; } = "-";
        public int M365AcceptedDomains { get; set; }
        public string M365DomainEvidence { get; set; } = "-";
        public int UniqueIps { get; set; }
        public int Asns { get; set; }
        public int Countries { get; set; }
        public string HttpGrade { get; set; } = "-";
        public int HttpMissingHeaders { get; set; }
        public string Hsts { get; set; } = "-";
    }

    private sealed class NameCountRow
    {
        public string Name { get; set; } = string.Empty;
        public int Count { get; set; }
    }

    private sealed class AsnCountRow
    {
        public int Asn { get; set; }
        public int Count { get; set; }
    }

    private sealed class PropagationRecordTypeRow
    {
        public string RecordType { get; set; } = string.Empty;
        public int Tests { get; set; }
        public int Inconsistent { get; set; }
        public int Servers { get; set; }
        public int Errors { get; set; }
    }

    private sealed class PropagationCountryRow
    {
        public string Country { get; set; } = string.Empty;
        public int Servers { get; set; }
        public int Success { get; set; }
        public int Errors { get; set; }
        public int Majority { get; set; }
        public int NonMajority { get; set; }
        public int Issues { get; set; }
    }

    private static void RenderDashboardDiscovery(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        if (page == null) throw new ArgumentNullException(nameof(page));
        if (ordered == null || ordered.Count == 0) return;

        var totalSubdomains = ordered.Sum(kv => kv.Value.Subdomains?.SubdomainCount ?? 0);
        var totalCt7d = ordered.Sum(kv => kv.Value.CtTimeline?.IssuedLast7Days ?? 0);
        var totalCt30d = ordered.Sum(kv => kv.Value.CtTimeline?.IssuedLast30Days ?? 0);
        var totalUniqueIps = ordered.Sum(kv => kv.Value.IpEnrichment?.UniqueIpCount ?? 0);
        var totalM365Domains = ordered.Count(kv => kv.Value.Microsoft365?.IsMicrosoft365Tenant == true);
        var totalM365Services = ordered.Sum(kv => kv.Value.Microsoft365?.Services?.Count(s => s.Status == DomainDetective.Microsoft365DetectionStatus.Detected) ?? 0);
        var totalM365AcceptedDomains = ordered.Sum(kv => CountAcceptedCustomDomains(kv.Value.Microsoft365?.TenantDomains));
        var domainsWithIp = ordered.Count(kv => kv.Value.IpEnrichment?.QuerySucceeded == true && (kv.Value.IpEnrichment?.UniqueIpCount ?? 0) > 0);
        var domainsWithHttp = ordered.Count(kv => kv.Value.Http != null);
        var domainsHttpReachable = ordered.Count(kv => kv.Value.Http?.IsReachable == true);
        var domainsWithHsts = ordered.Count(kv => kv.Value.Http?.HstsPresent == true);
        var uniqueAsns = new HashSet<int>();
        var asnCounts = new Dictionary<int, int>();
        var countryCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in ordered)
        {
            var ip = kv.Value.IpEnrichment;
            if (ip?.AsnCounts == null) continue;
            foreach (var a in ip.AsnCounts)
            {
                uniqueAsns.Add(a.Key);
                asnCounts[a.Key] = asnCounts.TryGetValue(a.Key, out var c) ? c + a.Value : a.Value;
            }
            if (ip.CountryCounts != null)
            {
                foreach (var c in ip.CountryCounts)
                {
                    if (string.IsNullOrWhiteSpace(c.Key)) continue;
                    countryCounts[c.Key] = countryCounts.TryGetValue(c.Key, out var existing) ? existing + c.Value : c.Value;
                }
            }
        }

        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            c.Card(card =>
            {
                card.Header(h => h.Title("Discovery & Inventory (Dashboard)"));
                card.Body(b =>
                {
                    b.DataGrid(g =>
                    {
                        g.AsCompact();
                        g.AddItem("Domains", ordered.Count.ToString()).AsPanel(TablerColor.Blue, light: true);
                        g.AddItem("Total Subdomains", totalSubdomains.ToString()).AsPanel(TablerColor.Indigo, light: true);
                        g.AddItem("CT Issued (7d)", totalCt7d.ToString()).AsPanel(TablerColor.Cyan, light: true);
                        g.AddItem("CT Issued (30d)", totalCt30d.ToString()).AsPanel(TablerColor.Cyan, light: true);
                        g.AddItem("M365 Domains", totalM365Domains.ToString()).AsPanel(TablerColor.Azure, light: true);
                        g.AddItem("M365 Services", totalM365Services.ToString()).AsPanel(TablerColor.Blue, light: true);
                        g.AddItem("M365 Accepted Domains", totalM365AcceptedDomains.ToString()).AsPanel(TablerColor.Indigo, light: true);
                        g.AddItem("Unique ASNs", uniqueAsns.Count.ToString()).AsPanel(TablerColor.Teal, light: true);
                        g.AddItem("Total Unique IPs", totalUniqueIps.ToString()).AsPanel(TablerColor.Teal, light: true);
                        g.AddItem("Domains (IP Data)", domainsWithIp.ToString()).AsPanel(TablerColor.Azure, light: true);
                        g.AddItem("Domains (HTTP)", domainsWithHttp.ToString()).AsPanel(TablerColor.Azure, light: true);
                        g.AddItem("HTTP Reachable", domainsHttpReachable.ToString()).AsPanel(TablerColor.Green, light: true);
                        g.AddItem("HSTS Enabled", domainsWithHsts.ToString()).AsPanel(TablerColor.Green, light: true);
                    });

                    var rows = ordered.Select(kv => new DiscoveryOverviewRow
                    {
                        Domain = kv.Key,
                        Subdomains = kv.Value.Subdomains?.SubdomainCount ?? 0,
                        CtUniqueCerts = kv.Value.CtTimeline?.UniqueCertificateCount ?? 0,
                        CtIssued7d = kv.Value.CtTimeline?.IssuedLast7Days ?? 0,
                        CtIssued30d = kv.Value.CtTimeline?.IssuedLast30Days ?? 0,
                        DnsProvider = kv.Value.DnsInventory != null ? kv.Value.DnsInventory.Provider.ToString() : "-",
                        MailProvider = kv.Value.DnsInventory != null ? kv.Value.DnsInventory.MailProvider.ToString() : "-",
                        Microsoft365 = kv.Value.Microsoft365?.Status ?? "-",
                        M365Confidence = kv.Value.Microsoft365?.DetectionConfidence.ToString() ?? "-",
                        M365Services = kv.Value.Microsoft365?.Services?.Count(s => s.Status == DomainDetective.Microsoft365DetectionStatus.Detected) ?? 0,
                        M365WorkloadEvidence = DescribeM365WorkloadEvidence(kv.Value.Microsoft365?.Services),
                        M365AcceptedDomains = CountAcceptedCustomDomains(kv.Value.Microsoft365?.TenantDomains),
                        M365DomainEvidence = DescribeM365DomainEvidence(kv.Value.Microsoft365?.TenantDomains),
                        UniqueIps = kv.Value.IpEnrichment?.UniqueIpCount ?? 0,
                        Asns = kv.Value.IpEnrichment?.DistinctAsnCount ?? 0,
                        Countries = kv.Value.IpEnrichment?.DistinctCountryCount ?? 0,
                        HttpGrade = kv.Value.Http != null && kv.Value.Http.Grade != GradeLevel.Unknown ? kv.Value.Http.Grade.ToString() : "-",
                        HttpMissingHeaders = kv.Value.Http?.MissingSecurityHeaders?.Count ?? 0,
                        Hsts = kv.Value.Http == null ? "-" : (kv.Value.Http.HstsPresent ? "Yes" : "No")
                    }).ToList();

                    var t = (DataTablesTable)b.Table(rows, TableType.DataTables);
                    ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                    t.EnablePaging(10, new[] { 10, 25, 50 })
                        .EnableSearching()
                        .EnableOrdering();
                });
            });
        }));

        // Aggregates / top lists
        var dnsProviderCounts = ordered
            .Where(kv => kv.Value.DnsInventory != null)
            .Select(kv => kv.Value.DnsInventory!.Provider)
            .Where(p => p != DnsProvider.Unknown)
            .GroupBy(p => p)
            .Select(g => new NameCountRow { Name = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();

        var mailProviderCounts = ordered
            .Where(kv => kv.Value.DnsInventory != null)
            .Select(kv => kv.Value.DnsInventory!.MailProvider)
            .Where(p => p != MailProviderKind.Unknown)
            .GroupBy(p => p)
            .Select(g => new NameCountRow { Name = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();

        var m365ConfidenceCounts = ordered
            .Where(kv => kv.Value.Microsoft365?.IsMicrosoft365Tenant == true)
            .GroupBy(kv => kv.Value.Microsoft365!.DetectionConfidence)
            .Select(g => new NameCountRow { Name = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var m365DomainEvidenceCounts = ordered
            .SelectMany(kv => kv.Value.Microsoft365?.TenantDomains ?? Array.Empty<DomainDetective.Microsoft365TenantDomain>())
            .Where(static domain => domain.Role != DomainDetective.Microsoft365TenantDomainRole.Unknown)
            .GroupBy(static domain => domain.Role)
            .Select(g => new NameCountRow { Name = FormatM365DomainRole(g.Key), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var m365WorkloadEvidenceCounts = ordered
            .SelectMany(kv => kv.Value.Microsoft365?.Services ?? Array.Empty<DomainDetective.Microsoft365ServiceDetection>())
            .Where(static service =>
                service.Status == DomainDetective.Microsoft365DetectionStatus.Detected &&
                service.EvidenceSource != DomainDetective.Microsoft365ServiceEvidenceSourceKind.Unknown)
            .GroupBy(static service => service.EvidenceSource)
            .Select(g => new NameCountRow { Name = FormatM365WorkloadEvidenceSource(g.Key), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => GetM365WorkloadEvidenceSortOrder(r.Name))
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var m365TenantBoostedCount = ordered
            .SelectMany(kv => kv.Value.Microsoft365?.Services ?? Array.Empty<DomainDetective.Microsoft365ServiceDetection>())
            .Count(static service => service.Status == DomainDetective.Microsoft365DetectionStatus.Detected && service.TenantContextBoosted);

        var topAsns = asnCounts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key)
            .Take(10)
            .Select(kv => new AsnCountRow { Asn = kv.Key, Count = kv.Value })
            .ToList();

        var topCountries = countryCounts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .Select(kv => new NameCountRow { Name = kv.Key, Count = kv.Value })
            .ToList();

        var gradeCounts = ordered
            .Where(kv => kv.Value.Http != null && kv.Value.Http.Grade != GradeLevel.Unknown)
            .GroupBy(kv => kv.Value.Http!.Grade)
            .Select(g => new NameCountRow { Name = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // DNS propagation (global multi-resolver visibility) aggregates
        var propagation = ordered
            .SelectMany(kv => kv.Value.DnsPropagation ?? new List<DomainDetective.Views.DnsPropagationInfo>())
            .Where(x => x != null)
            .ToList();

        var domainsWithPropagation = ordered.Count(kv => kv.Value.DnsPropagation != null && kv.Value.DnsPropagation.Count > 0);
        var propagationTests = propagation.Count;
        var propagationInconsistent = propagation.Count(p => p.QuerySucceeded && p.DistinctAnswerSets > 1);
        var propagationServers = propagation.Sum(p => p.ServerCount);
        var propagationServerErrors = propagation.Sum(p => p.ServerErrorCount);

        var propagationByType = propagation
            .GroupBy(p => p.RecordType)
            .Select(g => new PropagationRecordTypeRow
            {
                RecordType = g.Key.ToString(),
                Tests = g.Count(),
                Inconsistent = g.Count(x => x.QuerySucceeded && x.DistinctAnswerSets > 1),
                Servers = g.Sum(x => x.ServerCount),
                Errors = g.Sum(x => x.ServerErrorCount)
            })
            .OrderByDescending(r => r.Tests)
            .ThenBy(r => r.RecordType, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var propagationCountries = new Dictionary<string, (int Servers, int Errors, int Majority, int NonMajority)>(StringComparer.OrdinalIgnoreCase);
        var propagationIssuesByIso2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var propagationCoverageByIso2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var anyCapped = propagation.Any(p => p.ResultsCapped);

        void EnsureCountry(string country)
        {
            if (!propagationCountries.ContainsKey(country))
            {
                propagationCountries[country] = (0, 0, 0, 0);
            }
        }

        foreach (var dp in propagation)
        {
            var results = dp.Results ?? Array.Empty<DomainDetective.DnsPropagationResult>();

            // Total servers + errors (from raw results)
            foreach (var r in results)
            {
                if (r?.Server == null || !r.Server.Country.HasValue) continue;

                var country = DomainDetective.CountryIdExtensions.ToName(r.Server.Country.Value);
                if (string.IsNullOrWhiteSpace(country)) continue;

                EnsureCountry(country);
                var agg = propagationCountries[country];
                agg.Servers++;

                if (TryGetIso2Code(country, out var iso2))
                {
                    if (!propagationCoverageByIso2.ContainsKey(iso2)) propagationCoverageByIso2[iso2] = 0;
                    propagationCoverageByIso2[iso2] += 1;
                }

                if (!r.Success)
                {
                    agg.Errors++;
                    if (TryGetIso2Code(country, out var iso2e))
                    {
                        if (!propagationIssuesByIso2.ContainsKey(iso2e)) propagationIssuesByIso2[iso2e] = 0;
                        propagationIssuesByIso2[iso2e] += 1;
                    }
                }

                propagationCountries[country] = agg;
            }

            // Majority vs non-majority (from answer sets)
            try
            {
                var groups = DomainDetective.DnsPropagationAnalysis.CompareResults(results);
                var majority = dp.MajorityAnswerSet;
                if (string.IsNullOrWhiteSpace(majority))
                {
                    majority = groups
                        .OrderByDescending(kv => kv.Value?.Count ?? 0)
                        .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(kv => kv.Key)
                        .FirstOrDefault();
                }

                foreach (var kv in groups)
                {
                    var isMajority = !string.IsNullOrWhiteSpace(majority) && string.Equals(kv.Key, majority, StringComparison.OrdinalIgnoreCase);
                    foreach (var e in kv.Value ?? new List<DomainDetective.DnsComparisonEntry>())
                    {
                        if (e == null || !e.Country.HasValue) continue;
                        var country = DomainDetective.CountryIdExtensions.ToName(e.Country.Value);
                        if (string.IsNullOrWhiteSpace(country)) continue;

                        EnsureCountry(country);
                        var agg = propagationCountries[country];
                        if (isMajority) agg.Majority++; else agg.NonMajority++;
                        propagationCountries[country] = agg;

                        if (!isMajority && TryGetIso2Code(country, out var iso2))
                        {
                            if (!propagationIssuesByIso2.ContainsKey(iso2)) propagationIssuesByIso2[iso2] = 0;
                            propagationIssuesByIso2[iso2] += 1;
                        }
                    }
                }
            }
            catch
            {
            }
        }

        var propagationCountryRows = propagationCountries
            .Select(kv =>
            {
                var servers = kv.Value.Servers;
                var errors = kv.Value.Errors;
                var success = Math.Max(0, servers - errors);
                var maj = kv.Value.Majority;
                var nonMaj = kv.Value.NonMajority;
                return new PropagationCountryRow
                {
                    Country = kv.Key,
                    Servers = servers,
                    Success = success,
                    Errors = errors,
                    Majority = maj,
                    NonMajority = nonMaj,
                    Issues = errors + nonMaj
                };
            })
            .OrderByDescending(r => r.Issues)
            .ThenByDescending(r => r.Servers)
            .ThenBy(r => r.Country, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();

        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            c.Row(rr =>
            {
                rr.Column(TablerColumnNumber.Four, c1 =>
                {
                    c1.Card(card =>
                    {
                        card.Header(h => h.Title("Provider Mix"));
                        card.Body(b =>
                        {
                            if (dnsProviderCounts.Count == 0 && mailProviderCounts.Count == 0)
                            {
                                b.Text("No provider data available.").Style(TablerTextStyle.Muted);
                                return;
                            }

                            if (dnsProviderCounts.Count > 0)
                            {
                                b.Text("DNS (top)").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(dnsProviderCounts, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }

                            if (mailProviderCounts.Count > 0)
                            {
                                b.Text("Mail (top)").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(mailProviderCounts, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }

                            if (m365ConfidenceCounts.Count > 0)
                            {
                                b.Text("Microsoft 365 Footprint").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(m365ConfidenceCounts, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }

                            if (m365DomainEvidenceCounts.Count > 0)
                            {
                                b.Text("M365 Domain Evidence").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(m365DomainEvidenceCounts, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }

                            if (m365WorkloadEvidenceCounts.Count > 0)
                            {
                                b.Text("M365 Workload Evidence").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(m365WorkloadEvidenceCounts, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }

                            if (m365TenantBoostedCount > 0)
                            {
                                b.Text($"Tenant-boosted workloads: {m365TenantBoostedCount}").Style(TablerTextStyle.Muted);
                            }
                        });
                    });
                });

                rr.Column(TablerColumnNumber.Four, c2 =>
                {
                    c2.Card(card =>
                    {
                        card.Header(h => h.Title("IP Footprint"));
                        card.Body(b =>
                        {
                            if (topAsns.Count == 0 && topCountries.Count == 0)
                            {
                                b.Text("No IP enrichment data available.").Style(TablerTextStyle.Muted);
                                return;
                            }

                            if (topAsns.Count > 0)
                            {
                                b.Text("Top ASNs").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(topAsns, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }

                            if (topCountries.Count > 0)
                            {
                                b.Text("Top Countries").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(topCountries, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                        });
                    });
                });

                rr.Column(TablerColumnNumber.Four, c3 =>
                {
                    c3.Card(card =>
                    {
                        card.Header(h => h.Title("HTTP Posture"));
                        card.Body(b =>
                        {
                            var kv = new List<(string Key, string Value)>
                            {
                                ("Domains (HTTP)", domainsWithHttp.ToString()),
                                ("Reachable", domainsHttpReachable.ToString()),
                                ("HSTS Enabled", domainsWithHsts.ToString())
                            };
                            var kvRows = kv.Select(x => new { x.Key, x.Value }).ToList();
                            var table = (TablerTable)b.Table(kvRows, TableType.Tabler);
                            table.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);

                            if (gradeCounts.Count > 0)
                            {
                                b.Text("Grades").Style(TablerTextStyle.Muted);
                                var t = (TablerTable)b.Table(gradeCounts, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                            else
                            {
                                b.Text("No HTTP grade data available.").Style(TablerTextStyle.Muted);
                            }
                        });
                    });
                });
            });
        }));

        // DNS propagation rollups
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            c.Row(rr =>
            {
                rr.Column(TablerColumnNumber.Four, c1 =>
                {
                    c1.Card(card =>
                    {
                        card.Header(h => h.Title("DNS Propagation"));
                        card.Body(b =>
                        {
                            if (propagationTests == 0)
                            {
                                b.Text("No DNS propagation data available.").Style(TablerTextStyle.Muted);
                                return;
                            }

                            b.DataGrid(g =>
                            {
                                g.AsCompact();
                                g.AddItem("Domains", domainsWithPropagation.ToString()).AsPanel(TablerColor.Blue, light: true);
                                g.AddItem("Tests", propagationTests.ToString()).AsPanel(TablerColor.Azure, light: true);
                                g.AddItem("Inconsistent", propagationInconsistent.ToString()).AsPanel(propagationInconsistent > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                g.AddItem("Server Errors", propagationServerErrors.ToString()).AsPanel(propagationServerErrors > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            });

                            if (anyCapped)
                            {
                                b.Alert("Capped results", "Some propagation results were capped; rollups are best-effort.", TablerColor.Orange)
                                    .Icon(TablerIconType.InfoCircle);
                            }

                            var (levels, caption, baseColor) = propagationIssuesByIso2.Count > 0
                                ? (ScaleToLevels(propagationIssuesByIso2), "Darker red indicates more issues (errors + non‑majority answers).", TablerColor.Red)
                                : (ScaleToLevels(propagationCoverageByIso2), "Darker blue indicates more resolver coverage (servers queried).", TablerColor.Blue);

                            if (levels.Count > 0)
                            {
                                b.VectorMap(vm =>
                                {
                                    vm.UseMap(JsVectorMapName.WorldMerc)
                                        .Settings(s =>
                                        {
                                            s.Height("220px");
                                            s.ZoomButtons(false);
                                            s.ZoomOnScroll(false);
                                        })
                                        .ColorRegions(levels, baseColor: baseColor, minAlpha: 0.15, maxAlpha: 0.95);
                                });
                                b.Text(caption).Style(TablerTextStyle.Muted);
                            }
                            else
                            {
                                b.Text("No mappable country data was found for propagation results.").Style(TablerTextStyle.Muted);
                            }
                        });
                    });
                });

                rr.Column(TablerColumnNumber.Four, c2 =>
                {
                    c2.Card(card =>
                    {
                        card.Header(h => h.Title("Propagation by Record Type"));
                        card.Body(b =>
                        {
                            if (propagationByType.Count == 0)
                            {
                                b.Text("No DNS propagation data available.").Style(TablerTextStyle.Muted);
                                return;
                            }

                            var t = (TablerTable)b.Table(propagationByType, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        });
                    });
                });

                rr.Column(TablerColumnNumber.Four, c3 =>
                {
                    c3.Card(card =>
                    {
                        card.Header(h => h.Title("Propagation Hotspots"));
                        card.Body(b =>
                        {
                            if (propagationCountryRows.Count == 0)
                            {
                                b.Text("No country rollups available.").Style(TablerTextStyle.Muted);
                                return;
                            }

                            var t = (TablerTable)b.Table(propagationCountryRows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        });
                    });
                });
            });
        }));
    }

    private static int CountAcceptedCustomDomains(IReadOnlyList<DomainDetective.Microsoft365TenantDomain>? domains)
    {
        if (domains == null || domains.Count == 0)
        {
            return 0;
        }

        return domains.Count(static domain => domain.Role == DomainDetective.Microsoft365TenantDomainRole.AcceptedCustomDomain);
    }

    private static string DescribeM365DomainEvidence(IReadOnlyList<DomainDetective.Microsoft365TenantDomain>? domains)
    {
        if (domains == null || domains.Count == 0)
        {
            return "-";
        }

        var values = domains
            .Where(static domain => domain.Role != DomainDetective.Microsoft365TenantDomainRole.Unknown)
            .GroupBy(static domain => domain.Role)
            .OrderBy(static group => GetM365DomainRoleSortOrder(group.Key))
            .ThenBy(static group => group.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Take(4)
            .Select(group => $"{FormatM365DomainRole(group.Key)} {group.Count()}")
            .ToList();

        return values.Count == 0 ? "-" : string.Join(", ", values);
    }

    private static string DescribeM365WorkloadEvidence(IReadOnlyList<DomainDetective.Microsoft365ServiceDetection>? services)
    {
        if (services == null || services.Count == 0)
        {
            return "-";
        }

        var detected = services
            .Where(static service => service.Status == DomainDetective.Microsoft365DetectionStatus.Detected)
            .ToList();
        if (detected.Count == 0)
        {
            return "-";
        }

        var values = detected
            .Where(static service => service.EvidenceSource != DomainDetective.Microsoft365ServiceEvidenceSourceKind.Unknown)
            .GroupBy(static service => service.EvidenceSource)
            .OrderBy(static group => GetM365WorkloadEvidenceSortOrder(FormatM365WorkloadEvidenceSource(group.Key)))
            .ThenBy(static group => group.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Take(4)
            .Select(group => $"{FormatM365WorkloadEvidenceSource(group.Key)} {group.Count()}")
            .ToList();

        var boosted = detected.Count(static service => service.TenantContextBoosted);
        if (boosted > 0)
        {
            values.Add($"Boosted {boosted}");
        }

        return values.Count == 0 ? "-" : string.Join(", ", values);
    }

    private static int GetM365DomainRoleSortOrder(DomainDetective.Microsoft365TenantDomainRole role)
    {
        switch (role)
        {
            case DomainDetective.Microsoft365TenantDomainRole.Primary:
                return 0;
            case DomainDetective.Microsoft365TenantDomainRole.IdentityDomain:
                return 1;
            case DomainDetective.Microsoft365TenantDomainRole.AcceptedCustomDomain:
                return 2;
            case DomainDetective.Microsoft365TenantDomainRole.MicrosoftManagedNamespace:
                return 3;
            case DomainDetective.Microsoft365TenantDomainRole.Unknown:
            default:
                return int.MaxValue;
        }
    }

    private static string FormatM365DomainRole(DomainDetective.Microsoft365TenantDomainRole role)
    {
        switch (role)
        {
            case DomainDetective.Microsoft365TenantDomainRole.Primary:
                return "Primary";
            case DomainDetective.Microsoft365TenantDomainRole.IdentityDomain:
                return "Identity-derived";
            case DomainDetective.Microsoft365TenantDomainRole.AcceptedCustomDomain:
                return "DKIM-derived";
            case DomainDetective.Microsoft365TenantDomainRole.MicrosoftManagedNamespace:
                return "Namespace-derived";
            case DomainDetective.Microsoft365TenantDomainRole.Unknown:
            default:
                return "Unknown";
        }
    }

    private static string FormatM365WorkloadEvidenceSource(DomainDetective.Microsoft365ServiceEvidenceSourceKind source)
    {
        switch (source)
        {
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.IdentityProbe:
                return "Identity";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.MailProtocol:
                return "Mail/Protocol";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.KnownSubdomain:
                return "Subdomain";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.DnsApplication:
                return "DNS App";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.Unknown:
            default:
                return "Unknown";
        }
    }

    private static int GetM365WorkloadEvidenceSortOrder(string source)
    {
        switch (source)
        {
            case "Identity":
                return 0;
            case "Mail/Protocol":
                return 1;
            case "Subdomain":
                return 2;
            case "DNS App":
                return 3;
            case "Unknown":
            default:
                return int.MaxValue;
        }
    }
}
