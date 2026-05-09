using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Excel composition across mixed view items (Index, Overview, per-domain sheets).
/// Implemented using OfficeIMO.Excel.
/// </summary>
public static partial class ExcelCompositionReport {
    private static Action<SheetComposer.ColumnComposer>? BuildMailTlsBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.SmtpTls == null && bucket.ImapTls == null && bucket.PopTls == null)
        {
            return null;
        }

        return column =>
        {
            column.Section("MailTLS");

            void Render(string label, DomainDetective.Views.MailTlsInfo? info)
            {
                if (info == null)
                {
                    return;
                }

                column.Section(label);
                if (info.Servers != null && info.Servers.Count > 0)
                {
                    var rows = info.Servers.Select(v => new
                    {
                        Server = v.Key,
                        Grade = v.Grade.ToString(),
                        CertValid = v.CertificateValid ? "Yes" : "No",
                        Chain = v.ChainValid ? "Yes" : "No",
                        DaysToExp = v.DaysToExpire,
                        Expired = v.IsExpired ? "Yes" : "No",
                        Proto = v.Protocol,
                        TLS13 = v.Tls13Used ? "Yes" : (v.SupportsTls13 ? "Supported" : "No"),
                        Cipher = v.CipherSuite,
                        Issuer = v.Issuer,
                        ValidTo = v.ValidTo?.ToString("yyyy-MM-dd") ?? string.Empty
                    }).ToList();

                    var range = column.TableFrom(rows, title: $"{label} Servers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.NumericColumnFormats["DaysToExp"] = "0";
                        v.FreezeHeaderRow = true;
                        v.TextBackgrounds["Grade"] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            { "A", "#D1E7DD" },
                            { "B", "#E2E3FF" },
                            { "C", "#FFF4CE" },
                            { "D", "#F8D7DA" },
                            { "F", "#F8D7DA" }
                        };
                    });

                    composer.ApplyColumnSizing(range, opt =>
                    {
                        opt.MediumHeaders.UnionWith(new[] { "Server", "Proto", "Cipher", "Issuer" });
                        opt.ShortHeaders.UnionWith(new[] { "Grade", "CertValid", "Chain", "Hostname", "TLS13", "DaysToExp", "Expired", "ValidTo" });
                        opt.WrapHeaders.Add("Server");
                    });
                }
            }

            Render("SMTP", bucket.SmtpTls);
            Render("IMAP", bucket.ImapTls);
            Render("POP3", bucket.PopTls);
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildMxBlock(DomainBucket bucket)
    {
        if (bucket.Mx == null)
        {
            return null;
        }

        var mx = bucket.Mx;
        return column =>
        {
            column.Section("MX").KeyValues(new (string, object?)[]
            {
                ("Record Present", mx.MxRecordExists ? "Yes" : "No"),
                ("IPv6 Supported", mx.Ipv6Supported ? "Yes" : "No"),
                ("Has Backup Servers", mx.HasBackupServers ? "Yes" : "No"),
                ("Null MX", mx.HasNullMx ? "Yes" : "No"),
                ("Priorities In Order", mx.PrioritiesInOrder ? "Yes" : "No"),
                ("TTL Uniform", mx.MxTtlUniform ? "Yes" : "No"),
                ("MX TTL Min (s)", mx.MinMxTtl?.ToString() ?? "-"),
                ("MX TTL Avg (s)", mx.AvgMxTtl.HasValue ? ((int)Math.Round(mx.AvgMxTtl.Value)).ToString() : "-"),
                ("MX TTL Max (s)", mx.MaxMxTtl?.ToString() ?? "-"),
                ("Points to CNAME", mx.PointsToCname ? "Yes" : "No"),
                ("Points to IP", mx.PointsToIpAddress ? "Yes" : "No"),
                ("Target Consistent Across NS", mx.TargetAddressConsistentAcrossNs ? "Yes" : "No")
            });

            var mxRecords = mx.MxRecords;
            if (mxRecords != null && mxRecords.Count > 0)
            {
                var rows = mxRecords.Select(r => new { Host = r }).ToList();
                column.TableFrom(rows, title: "MX Records", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            var mxRecommendations = mx.Recommendations;
            if (mxRecommendations != null && mxRecommendations.Count > 0)
            {
                column.Section("Recommendations").BulletedList(mxRecommendations.Select(r => r.Title ?? r.Code).ToArray());
            }

            var mxPositives = mx.Positives;
            if (mxPositives != null && mxPositives.Count > 0)
            {
                column.Section("Positives").BulletedList(mxPositives.Select(p => p.Title ?? p.Code).ToArray());
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildArcBlock(DomainBucket bucket)
    {
        if (bucket.Arc == null)
        {
            return null;
        }

        var arc = bucket.Arc;
        return column =>
        {
            column.Section("ARC").KeyValues(new (string, object?)[]
            {
                ("ARC Headers Present", arc.ArcHeadersFound ? "Yes" : "No"),
                ("Seal Count", arc.SealCount),
                ("AAR Count", arc.AarCount),
                ("Valid Chain", arc.ValidChain ? "Yes" : "No"),
                ("Chain State", arc.ChainState)
            });

            var arcHighlights = arc.Highlights;
            if (arcHighlights != null && arcHighlights.Count > 0)
            {
                column.Section("Highlights").BulletedList(arcHighlights);
            }

            var arcRecommendations = arc.Recommendations;
            if (arcRecommendations != null && arcRecommendations.Count > 0)
            {
                column.Section("Recommendations").BulletedList(arcRecommendations.Select(r => r.Title ?? r.Code).ToArray());
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDnssecDaneBlock(DomainBucket bucket)
    {
        if (bucket.Dnssec == null && bucket.Dane == null)
        {
            return null;
        }

        return column =>
        {
            var rows = new List<(string, object?)>();
            if (bucket.Dnssec != null)
            {
                rows.Add(("DNSSEC", bucket.Dnssec.Status ?? "-"));
            }
            if (bucket.Dane != null)
            {
                rows.Add(("DANE", bucket.Dane.Status ?? "-"));
            }

            if (rows.Count > 0)
            {
                column.Section("DNSSEC/DANE").KeyValues(rows);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDnsblBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.Dnsbl == null)
        {
            return null;
        }

        var dnsbl = bucket.Dnsbl;
        return column =>
        {
            column.Section("DNSBL").KeyValues(new (string, object?)[]
            {
                ("Providers Checked", dnsbl.ProvidersChecked),
                ("Hosts Checked", dnsbl.HostsChecked),
                ("Hosts Listed", dnsbl.HostsListed)
            });

            if (dnsbl.HostSummaries != null && dnsbl.HostSummaries.Count > 0)
            {
                var hostRows = dnsbl.HostSummaries.Select(h => new
                {
                    Host = h.Key,
                    Listed = h.Listed,
                    Total = h.Total,
                    Blacklists = string.Join(", ", h.Blacklists ?? new List<string>())
                }).ToList();
                var range = column.TableFrom(hostRows, title: "Host Summaries", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Listed"] = "0";
                    v.NumericColumnFormats["Total"] = "0";
                    v.FreezeHeaderRow = true;
                });

                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.MediumHeaders.Add("Host");
                    opt.NumericHeaders.UnionWith(new[] { "Listed", "Total" });
                    opt.LongHeaders.Add("Blacklists");
                    opt.WrapHeaders.Add("Blacklists");
                });
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildNsBlock(DomainBucket bucket)
    {
        if (bucket.Ns == null)
        {
            return null;
        }

        var ns = bucket.Ns;
        return column =>
        {
            column.Section("Name Servers").KeyValues(new (string, object?)[]
            {
                ("Records Present", ns.NsRecordExists ? "Yes" : "No"),
                ("Record Count", ns.NsRecords?.Count ?? 0),
                ("Has Duplicates", ns.HasDuplicates ? "Yes" : "No"),
                ("ASN Diversity", ns.AsnDistinctCount),
                ("Geo Diverse", ns.HasDiverseLocations ? "Yes" : "No"),
                ("Delegation Matches", ns.DelegationMatches ? "Yes" : "No")
            });

            var nsRecords = ns.NsRecords;
            if (nsRecords != null && nsRecords.Count > 0)
            {
                var rows = nsRecords.Select(host => new { Host = host }).ToList();
                column.TableFrom(rows, title: "Authoritative NS", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            var parentNsRecords = ns.ParentNsRecords;
            if (parentNsRecords != null && parentNsRecords.Count > 0)
            {
                var rows = parentNsRecords.Select(host => new { Parent = host }).ToList();
                column.TableFrom(rows, title: "Parent Delegation", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildSoaBlock(DomainBucket bucket)
    {
        if (bucket.Soa == null)
        {
            return null;
        }

        var soa = bucket.Soa;
        return column =>
        {
            column.Section("SOA").KeyValues(new (string, object?)[]
            {
                ("Primary", string.IsNullOrWhiteSpace(soa.PrimaryNameServer) ? "-" : soa.PrimaryNameServer),
                ("Responsible", string.IsNullOrWhiteSpace(soa.ResponsibleMailbox) ? "-" : soa.ResponsibleMailbox),
                ("Serial", soa.SerialNumber),
                ("Serial Format Valid", soa.SerialFormatValid ? "Yes" : "No"),
                ("Refresh", soa.Refresh),
                ("Retry", soa.Retry),
                ("Expire", soa.Expire),
                ("Minimum", soa.Minimum),
                ("Neg Cache TTL", soa.NegativeCacheTtl)
            });

            if (!string.IsNullOrWhiteSpace(soa.SerialFormatSuggestion))
            {
                column.Section("Serial Suggestion").Paragraph(soa.SerialFormatSuggestion);
            }
        };
    }

}


