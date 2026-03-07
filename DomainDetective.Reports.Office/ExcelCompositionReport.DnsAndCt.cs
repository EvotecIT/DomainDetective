using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;
using SixLabors.ImageSharp;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Excel composition across mixed view items (Index, Overview, per-domain sheets).
/// Implemented using OfficeIMO.Excel.
/// </summary>
public static partial class ExcelCompositionReport {
    private static Action<SheetComposer.ColumnComposer>? BuildDnsInventoryBlock(DomainBucket bucket)
    {
        if (bucket.DnsInventory == null)
        {
            return null;
        }

        var inv = bucket.DnsInventory;
        return column =>
        {
            column.Section("DNS Inventory").KeyValues(new (string, object?)[]
            {
                ("Status", inv.Status ?? "-"),
                ("Query OK", inv.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(inv.FailureReason) ? "-" : inv.FailureReason),
                ("Types Queried", inv.RecordTypesQueried),
                ("Types Failed", inv.RecordTypesFailed),
                ("Records", inv.TotalRecords),
                ("Provider", inv.Provider != DomainDetective.Providers.Dns.DnsProvider.Unknown ? inv.Provider.ToString() : "-"),
                ("Mail Provider", inv.MailProvider != DomainDetective.Providers.Email.MailProviderKind.Unknown ? inv.MailProvider.ToString() : "-"),
                ("CNAME Provider", inv.CnameTargetProvider != DomainDetective.Providers.Dns.DnsCnameTargetProvider.Unknown ? inv.CnameTargetProvider.ToString() : "-"),
                ("CNAME Flags", inv.CnameTargetFlags != DomainDetective.Providers.Dns.DnsCnameTargetFlags.None ? inv.CnameTargetFlags.ToString() : "-"),
                ("TXT Signals", inv.TxtSignals != DomainDetective.Providers.Dns.DnsTxtSignals.None ? inv.TxtSignals.ToString() : "-"),
                ("CAA Issuers", inv.CaaIssuers != DomainDetective.Providers.Dns.DnsCaaIssuers.None ? inv.CaaIssuers.ToString() : "-"),
                ("Authority Included", inv.IncludeAuthorities ? "Yes" : "No"),
                ("Additional Included", inv.IncludeAdditional ? "Yes" : "No")
            });

            if (inv.ProviderEvidence != null && inv.ProviderEvidence.Count > 0)
            {
                column.Section("Provider Evidence").BulletedList(inv.ProviderEvidence.Take(10).ToArray());
            }

            if (inv.MailProviderEvidence != null && inv.MailProviderEvidence.Count > 0)
            {
                column.Section("Mail Provider Evidence").BulletedList(inv.MailProviderEvidence.Take(10).ToArray());
            }

            if (inv.CnameTargetEvidence != null && inv.CnameTargetEvidence.Count > 0)
            {
                column.Section("CNAME Evidence").BulletedList(inv.CnameTargetEvidence.Take(10).ToArray());
            }

            if (inv.TxtSignalsEvidence != null && inv.TxtSignalsEvidence.Count > 0)
            {
                column.Section("TXT Signals Evidence").BulletedList(inv.TxtSignalsEvidence.Take(10).ToArray());
            }

            if (inv.CaaIssuersEvidence != null && inv.CaaIssuersEvidence.Count > 0)
            {
                column.Section("CAA Evidence").BulletedList(inv.CaaIssuersEvidence.Take(10).ToArray());
            }

            var queries = inv.Queries;
            if (queries != null && queries.Count > 0)
            {
                var qrows = queries
                    .OrderBy(q => q.RecordType)
                    .Select(q => new
                    {
                        RecordType = q.RecordType,
                        Status = q.Status.ToString(),
                        Response = q.ResponseStatus.ToString(),
                        Records = q.Records.Count,
                        Failure = string.IsNullOrWhiteSpace(q.FailureReason) ? "-" : q.FailureReason
                    })
                    .ToList();

                column.TableFrom(qrows, title: "Query Results", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Records"] = "0";
                    v.FreezeHeaderRow = true;
                });

                const int maxRows = 200;
                var rows = new List<object>(Math.Min(inv.TotalRecords, maxRows));
                foreach (var q in queries)
                {
                    foreach (var r in q.Records)
                    {
                        if (rows.Count >= maxRows) break;
                        rows.Add(new
                        {
                            QueryType = q.RecordType,
                            Section = r.Section.ToString(),
                            RecordType = r.Type,
                            r.Name,
                            TTL = r.Ttl,
                            r.Data
                        });
                    }
                    if (rows.Count >= maxRows) break;
                }

                if (rows.Count > 0)
                {
                    column.TableFrom(rows, title: "Records (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.NumericColumnFormats["TTL"] = "0";
                        v.FreezeHeaderRow = true;
                    });
                }
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDnsTraceBlock(DomainBucket bucket)
    {
        if (bucket.DnsTrace == null)
        {
            return null;
        }

        var tr = bucket.DnsTrace;
        var projection = DomainDetective.Reports.SectionProjectors.BuildDnsTrace(tr);

        return column =>
        {
            var recordTypes = "-";
            try
            {
                if (tr.Raw?.RecordTypesToTrace != null && tr.Raw.RecordTypesToTrace.Length > 0)
                {
                    recordTypes = string.Join(", ", tr.Raw.RecordTypesToTrace.Select(x => x.ToString()));
                }
            }
            catch { }

            column.Section("DNS Trace").KeyValues(new (string, object?)[]
            {
                ("Status", tr.Status ?? "-"),
                ("Trace OK", tr.TraceSucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(tr.FailureReason) ? "-" : tr.FailureReason),
                ("Record Types", recordTypes),
                ("IPv6 Roots", tr.Raw?.IncludeIpv6RootServers == true ? "Yes" : "No"),
                ("Max Depth", tr.Raw?.MaxDepth.ToString() ?? "-"),
                ("Max Steps", tr.Raw?.MaxTotalSteps.ToString() ?? "-"),
                ("Queries", tr.TraceQueries),
                ("Queries Failed", tr.TraceQueriesFailed),
                ("Steps", tr.TotalSteps)
            });

            var queries = tr.Queries;
            if (queries != null && queries.Count > 0)
            {
                var qrows = queries
                    .OrderBy(q => q.RecordType)
                    .Select(q => new
                    {
                        RecordType = q.RecordType.ToString(),
                        Status = q.Status.ToString(),
                        FinalStatus = q.FinalResponseStatus.ToString(),
                        FinalName = string.IsNullOrWhiteSpace(q.FinalName) ? "-" : q.FinalName,
                        Steps = q.Steps.Count,
                        Failure = string.IsNullOrWhiteSpace(q.FailureReason) ? "-" : q.FailureReason
                    })
                    .ToList();

                column.TableFrom(qrows, title: "Trace Results", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Steps"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.Rows.Count > 0)
            {
                const int maxRows = 200;
                var rows = projection.Rows
                    .Take(maxRows)
                    .Select(r => new
                    {
                        Trace = r.TraceType.ToString(),
                        Kind = r.Kind.ToString(),
                        r.Depth,
                        r.Server,
                        r.Name,
                        Type = r.RecordType.ToString(),
                        Status = r.ResponseStatus.ToString(),
                        RTT = r.RttMs,
                        Next = r.NextServers
                    })
                    .ToList();

                column.TableFrom(rows, title: "Trace Steps (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Depth"] = "0";
                    v.NumericColumnFormats["RTT"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildCtTimelineBlock(DomainBucket bucket)
    {
        if (bucket.CtTimeline == null)
        {
            return null;
        }

        var ct = bucket.CtTimeline;
        var projection = DomainDetective.Reports.SectionProjectors.BuildCtTimeline(ct);

        return column =>
        {
            column.Section("CT Timeline").KeyValues(new (string, object?)[]
            {
                ("Status", ct.Status ?? "-"),
                ("Query OK", ct.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(ct.FailureReason) ? "-" : ct.FailureReason),
                ("Observations", ct.CertificateObservationCount),
                ("Unique Certificates", ct.UniqueCertificateCount),
                ("Active", ct.ActiveCertificateCount),
                ("Expired", ct.ExpiredCertificateCount),
                ("Not Yet Valid", ct.NotYetValidCertificateCount),
                ("Wildcards", ct.WildcardCertificateCount),
                ("Issued (7d)", ct.IssuedLast7Days),
                ("Issued (30d)", ct.IssuedLast30Days),
                ("First Seen (UTC)", ct.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-"),
                ("Last Seen (UTC)", ct.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-"),
                ("Issuer Diversity", ct.IssuerCounts?.Count ?? 0),
                ("Capped", ct.ResultsCapped ? "Yes" : "No")
            });

            if (projection != null && projection.Timeline.Count > 0)
            {
                var rows = projection.Timeline
                    .Select(x => new { x.Month, Certificates = x.Certificates, Issuers = x.Issuers })
                    .ToList();

                column.TableFrom(rows, title: "Timeline (Monthly)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Certificates"] = "0";
                    v.NumericColumnFormats["Issuers"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.RecentCertificates.Count > 0)
            {
                const int maxRows = 200;
                var rows = projection.RecentCertificates
                    .Take(maxRows)
                    .Select(x => new
                    {
                        x.EntryUtc,
                        x.NotAfterUtc,
                        Validity = x.Validity.ToString(),
                        Wildcard = x.Wildcard ? "Yes" : "No",
                        x.Issuer,
                        x.CommonName
                    })
                    .ToList();

                column.TableFrom(rows, title: "Recent Certificates (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

}


