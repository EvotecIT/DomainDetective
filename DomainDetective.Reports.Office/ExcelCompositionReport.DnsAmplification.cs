#if NET8_0
using System;
using System.Globalization;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
#endif

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
#if NET8_0
    private static Action<SheetComposer.ColumnComposer>? BuildDnsAmplificationBlock(DomainBucket bucket)
    {
        if (bucket == null || bucket.DnsAmplification == null)
        {
            return null;
        }

        var amp = bucket.DnsAmplification;
        var projection = DomainDetective.Reports.SectionProjectors.BuildDnsAmplification(amp);
        if (projection == null)
        {
            return null;
        }

        return column =>
        {
            column.Section("DNS Amplification").KeyValues(new (string, object?)[]
            {
                ("Status", amp.Status ?? "-"),
                ("Servers", amp.TotalChecked),
                ("Open Recursion", amp.OpenRecursionCount),
                ("Large UDP", amp.LargeUdpResponseCount),
                ("Warnings", amp.WarningCount),
                ("Errors", amp.ErrorCount)
            });

            if (projection.Servers.Count > 0)
            {
                var rows = projection.Servers
                    .Take(200)
                    .Select(s => new
                    {
                        NameServer = s.NameServerHost,
                        Ip = s.ServerIp,
                        OpenRecursion = s.OpenRecursion,
                        Edns = s.EdnsSupported,
                        EdnsUdpSize = s.EdnsUdpPayloadSize.HasValue ? s.EdnsUdpPayloadSize.Value.ToString(CultureInfo.InvariantCulture) : "-",
                        UdpTruncated = s.EdnsTruncatedUdp,
                        WorstType = s.WorstProbeType,
                        WorstName = s.WorstProbeName,
                        WorstBytes = s.WorstProbeResponseBytes,
                        WorstAmp = s.WorstProbeAmplificationFactor.ToString("0.0", CultureInfo.InvariantCulture) + "x",
                        WorstTruncated = s.WorstProbeTruncated
                    })
                    .ToList();

                column.TableFrom(rows, title: "Name Servers (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["WorstBytes"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(f => new { f.Severity, f.Code, f.Target, f.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }
#endif
}
