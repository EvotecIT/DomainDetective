using System;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
    private static Action<SheetComposer.ColumnComposer>? BuildDnsPropagationBlock(DomainBucket bucket)
    {
        if (bucket == null || bucket.DnsPropagation == null || bucket.DnsPropagation.Count == 0)
        {
            return null;
        }

        var items = bucket.DnsPropagation
            .Where(i => i != null)
            .OrderBy(i => i.RecordType.ToString(), StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (items.Count == 0)
        {
            return null;
        }

        return column =>
        {
            column.Section("DNS Propagation").KeyValues(new (string, object?)[]
            {
                ("Tests", items.Count),
                ("Warnings", items.Sum(i => i.WarningCount)),
                ("Errors", items.Sum(i => i.ErrorCount)),
                ("Total Servers", items.Sum(i => i.ServerCount))
            });

            var summaryRows = items.Select(i => new
            {
                RecordType = i.RecordType.ToString(),
                Status = i.Status ?? "-",
                Servers = i.ServerCount,
                Success = i.ServerSuccessCount,
                Errors = i.ServerErrorCount,
                AnswerSets = i.DistinctAnswerSets,
                Majority = string.IsNullOrWhiteSpace(i.MajorityAnswerSet) ? "-" : i.MajorityAnswerSet
            }).ToList();

            column.TableFrom(summaryRows, title: "Record Types", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
            {
                v.NumericColumnFormats["Servers"] = "0";
                v.NumericColumnFormats["Success"] = "0";
                v.NumericColumnFormats["Errors"] = "0";
                v.NumericColumnFormats["AnswerSets"] = "0";
                v.FreezeHeaderRow = true;
            });

            foreach (var dp in items)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildDnsPropagation(dp);
                if (sec == null)
                {
                    continue;
                }

                if (sec.AnswerSets.Count > 0)
                {
                    var rows = sec.AnswerSets
                        .Take(50)
                        .Select(a => new { a.AnswerSetKey, a.Servers, a.Countries, a.Locations, a.SampleServers })
                        .ToList();
                    column.TableFrom(rows, title: $"Answer Sets ({dp.RecordType})", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.NumericColumnFormats["Servers"] = "0";
                        v.NumericColumnFormats["Countries"] = "0";
                        v.NumericColumnFormats["Locations"] = "0";
                        v.FreezeHeaderRow = true;
                    });
                }

                if (sec.Countries.Count > 0)
                {
                    var rows = sec.Countries
                        .Take(80)
                        .Select(c => new { c.Country, c.Servers, c.Success, c.Errors, c.Majority, c.NonMajority })
                        .ToList();
                    column.TableFrom(rows, title: $"Country Rollup ({dp.RecordType})", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.NumericColumnFormats["Servers"] = "0";
                        v.NumericColumnFormats["Success"] = "0";
                        v.NumericColumnFormats["Errors"] = "0";
                        v.NumericColumnFormats["Majority"] = "0";
                        v.NumericColumnFormats["NonMajority"] = "0";
                        v.FreezeHeaderRow = true;
                    });
                }

                if (sec.Servers.Count > 0)
                {
                    var rows = sec.Servers
                        .Take(200)
                        .Select(s => new
                        {
                            s.ServerIp,
                            s.Country,
                            s.Location,
                            ASN = string.IsNullOrWhiteSpace(s.Asn) ? "-" : "AS" + s.Asn,
                            s.Success,
                            RTTms = s.DurationMs,
                            Majority = s.IsMajority,
                            s.AnswerSetKey,
                            s.Answers,
                            s.Error
                        })
                        .ToList();

                    column.TableFrom(rows, title: $"Resolvers (Sample) ({dp.RecordType})", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.NumericColumnFormats["RTTms"] = "0";
                        v.FreezeHeaderRow = true;
                    });
                }

                if (sec.Findings.Count > 0)
                {
                    var rows = sec.Findings.Select(f => new { f.Severity, f.Code, f.Target, f.Message }).ToList();
                    column.TableFrom(rows, title: $"Findings ({dp.RecordType})", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.FreezeHeaderRow = true;
                    });
                }
            }
        };
    }
}
