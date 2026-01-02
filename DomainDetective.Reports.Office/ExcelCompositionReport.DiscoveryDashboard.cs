using System;
using System.Collections.Generic;
using System.Linq;
#if NET8_0
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
#endif
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
#if NET8_0
    private sealed class DiscoveryOverviewRow
    {
        public string Domain { get; init; } = string.Empty;
        public int Subdomains { get; init; }
        public int CtUniqueCerts { get; init; }
        public int CtIssued7d { get; init; }
        public int CtIssued30d { get; init; }
        public string DnsProvider { get; init; } = "-";
        public string MailProvider { get; init; } = "-";
        public int UniqueIps { get; init; }
        public int Asns { get; init; }
        public int Countries { get; init; }
        public string HttpGrade { get; init; } = "-";
        public int HttpMissingHeaders { get; init; }
        public string Hsts { get; init; } = "-";
    }

    private sealed class NameCountRow
    {
        public string Name { get; init; } = string.Empty;
        public int Count { get; init; }
    }

    private sealed class AsnCountRow
    {
        public int Asn { get; init; }
        public int Count { get; init; }
    }

    private sealed class PropagationRecordTypeRow
    {
        public string RecordType { get; init; } = "-";
        public int Tests { get; init; }
        public int Inconsistent { get; init; }
        public int Servers { get; init; }
        public int Errors { get; init; }
    }

    private sealed class PropagationCountryRow
    {
        public string Country { get; init; } = "-";
        public int Servers { get; init; }
        public int Success { get; init; }
        public int Errors { get; init; }
        public int Majority { get; init; }
        public int NonMajority { get; init; }
        public int Issues { get; init; }
    }

    private static void BuildDiscoveryDashboardSheet(ExcelDocument doc, List<KeyValuePair<string, DomainBucket>> domains)
    {
        var sheet = new SheetComposer(doc, "Discovery Dashboard");
        sheet.Title("Discovery Dashboard", $"Generated {DateTime.Now:yyyy-MM-dd HH:mm}");

        var totalSubdomains = domains.Sum(kv => kv.Value.Subdomains?.SubdomainCount ?? 0);
        var totalCt7d = domains.Sum(kv => kv.Value.CtTimeline?.IssuedLast7Days ?? 0);
        var totalCt30d = domains.Sum(kv => kv.Value.CtTimeline?.IssuedLast30Days ?? 0);
        var totalUniqueIps = domains.Sum(kv => kv.Value.IpEnrichment?.UniqueIpCount ?? 0);
        var domainsWithIp = domains.Count(kv => kv.Value.IpEnrichment?.QuerySucceeded == true && (kv.Value.IpEnrichment?.UniqueIpCount ?? 0) > 0);
        var domainsWithHttp = domains.Count(kv => kv.Value.Http != null);
        var domainsHttpReachable = domains.Count(kv => kv.Value.Http?.IsReachable == true);
        var domainsWithHsts = domains.Count(kv => kv.Value.Http?.HstsPresent == true);

        var uniqueAsns = new HashSet<int>();
        var asnCounts = new Dictionary<int, int>();
        var countryCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in domains)
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

        sheet.KpiRow(new (string, object?)[]
        {
            ("Domains", domains.Count),
            ("Total Subdomains", totalSubdomains),
            ("CT Issued (7d)", totalCt7d),
            ("CT Issued (30d)", totalCt30d),
            ("Unique ASNs", uniqueAsns.Count),
            ("Total Unique IPs", totalUniqueIps),
            ("Domains (IP Data)", domainsWithIp),
            ("Domains (HTTP)", domainsWithHttp),
            ("HTTP Reachable", domainsHttpReachable),
            ("HSTS Enabled", domainsWithHsts)
        }, perRow: 3);

        var rows = domains.Select(kv => new DiscoveryOverviewRow
        {
            Domain = kv.Key,
            Subdomains = kv.Value.Subdomains?.SubdomainCount ?? 0,
            CtUniqueCerts = kv.Value.CtTimeline?.UniqueCertificateCount ?? 0,
            CtIssued7d = kv.Value.CtTimeline?.IssuedLast7Days ?? 0,
            CtIssued30d = kv.Value.CtTimeline?.IssuedLast30Days ?? 0,
            DnsProvider = kv.Value.DnsInventory != null ? kv.Value.DnsInventory.Provider.ToString() : "-",
            MailProvider = kv.Value.DnsInventory != null ? kv.Value.DnsInventory.MailProvider.ToString() : "-",
            UniqueIps = kv.Value.IpEnrichment?.UniqueIpCount ?? 0,
            Asns = kv.Value.IpEnrichment?.DistinctAsnCount ?? 0,
            Countries = kv.Value.IpEnrichment?.DistinctCountryCount ?? 0,
            HttpGrade = kv.Value.Http != null && kv.Value.Http.Grade != GradeLevel.Unknown ? kv.Value.Http.Grade.ToString() : "-",
            HttpMissingHeaders = kv.Value.Http?.MissingSecurityHeaders?.Count ?? 0,
            Hsts = kv.Value.Http == null ? "-" : (kv.Value.Http.HstsPresent ? "Yes" : "No")
        }).ToList();

        sheet.TableFrom(rows, title: "Discovery Overview", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
        {
            v.NumericColumnFormats["Subdomains"] = "0";
            v.NumericColumnFormats["CtUniqueCerts"] = "0";
            v.NumericColumnFormats["CtIssued7d"] = "0";
            v.NumericColumnFormats["CtIssued30d"] = "0";
            v.NumericColumnFormats["UniqueIps"] = "0";
            v.NumericColumnFormats["Asns"] = "0";
            v.NumericColumnFormats["Countries"] = "0";
            v.NumericColumnFormats["HttpMissingHeaders"] = "0";
            v.FreezeHeaderRow = true;
        });

        // Provider Mix
        var dnsProviderRows = domains
            .Where(kv => kv.Value.DnsInventory != null && kv.Value.DnsInventory.Provider != DnsProvider.Unknown)
            .GroupBy(kv => kv.Value.DnsInventory!.Provider)
            .Select(g => new NameCountRow { Name = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .Take(15)
            .ToList();
        if (dnsProviderRows.Count > 0)
        {
            sheet.TableFrom(dnsProviderRows, title: "DNS Providers (Domains)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
            {
                v.NumericColumnFormats["Count"] = "0";
                v.FreezeHeaderRow = true;
            });
        }

        var mailProviderRows = domains
            .Where(kv => kv.Value.DnsInventory != null && kv.Value.DnsInventory.MailProvider != MailProviderKind.Unknown)
            .GroupBy(kv => kv.Value.DnsInventory!.MailProvider)
            .Select(g => new NameCountRow { Name = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .Take(15)
            .ToList();
        if (mailProviderRows.Count > 0)
        {
            sheet.TableFrom(mailProviderRows, title: "Mail Providers (Domains)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
            {
                v.NumericColumnFormats["Count"] = "0";
                v.FreezeHeaderRow = true;
            });
        }

        // IP footprint: top ASNs / countries (best-effort aggregate counts)
        var topAsnRows = asnCounts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key)
            .Take(20)
            .Select(kv => new AsnCountRow { Asn = kv.Key, Count = kv.Value })
            .ToList();
        if (topAsnRows.Count > 0)
        {
            sheet.TableFrom(topAsnRows, title: "Top ASNs (IP occurrences)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
            {
                v.NumericColumnFormats["Asn"] = "0";
                v.NumericColumnFormats["Count"] = "0";
                v.FreezeHeaderRow = true;
            });
        }

        var topCountryRows = countryCounts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .Select(kv => new NameCountRow { Name = kv.Key, Count = kv.Value })
            .ToList();
        if (topCountryRows.Count > 0)
        {
            sheet.TableFrom(topCountryRows, title: "Top Countries (IP occurrences)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
            {
                v.NumericColumnFormats["Count"] = "0";
                v.FreezeHeaderRow = true;
            });
        }

        // HTTP Grade distribution
        var httpGradeRows = domains
            .Where(kv => kv.Value.Http != null && kv.Value.Http.Grade != GradeLevel.Unknown)
            .GroupBy(kv => kv.Value.Http!.Grade)
            .Select(g => new NameCountRow { Name = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (httpGradeRows.Count > 0)
        {
            sheet.TableFrom(httpGradeRows, title: "HTTP Grades (Domains)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
            {
                v.NumericColumnFormats["Count"] = "0";
                v.FreezeHeaderRow = true;
            });
        }

        // DNS propagation (global multi-resolver visibility) aggregates
        var propagation = domains
            .SelectMany(kv => kv.Value.DnsPropagation ?? new List<DomainDetective.Views.DnsPropagationInfo>())
            .Where(x => x != null)
            .ToList();

        var domainsWithPropagation = domains.Count(kv => kv.Value.DnsPropagation != null && kv.Value.DnsPropagation.Count > 0);
        var propagationTests = propagation.Count;
        var propagationInconsistent = propagation.Count(p => p.QuerySucceeded && p.DistinctAnswerSets > 1);
        var propagationServers = propagation.Sum(p => p.ServerCount);
        var propagationServerErrors = propagation.Sum(p => p.ServerErrorCount);
        var anyCapped = propagation.Any(p => p.ResultsCapped);

        if (propagationTests > 0)
        {
            sheet.KpiRow(new (string, object?)[]
            {
                ("Domains (DNS Propagation)", domainsWithPropagation),
                ("Tests", propagationTests),
                ("Inconsistent", propagationInconsistent),
                ("Servers", propagationServers),
                ("Server Errors", propagationServerErrors),
                ("Capped", anyCapped ? "Yes" : "No")
            }, perRow: 3);

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
                .Take(20)
                .ToList();

            if (propagationByType.Count > 0)
            {
                sheet.TableFrom(propagationByType, title: "DNS Propagation by Record Type", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Tests"] = "0";
                    v.NumericColumnFormats["Inconsistent"] = "0";
                    v.NumericColumnFormats["Servers"] = "0";
                    v.NumericColumnFormats["Errors"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            var propagationCountries = new Dictionary<string, (int Servers, int Errors, int Majority, int NonMajority)>(StringComparer.OrdinalIgnoreCase);

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
                    if (!r.Success) agg.Errors++;
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
                .Take(20)
                .ToList();

            if (propagationCountryRows.Count > 0)
            {
                sheet.TableFrom(propagationCountryRows, title: "DNS Propagation Hotspots (Country)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Servers"] = "0";
                    v.NumericColumnFormats["Success"] = "0";
                    v.NumericColumnFormats["Errors"] = "0";
                    v.NumericColumnFormats["Majority"] = "0";
                    v.NumericColumnFormats["NonMajority"] = "0";
                    v.NumericColumnFormats["Issues"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }
        }

        sheet.Finish(autoFitColumns: true);
    }
#endif
}
