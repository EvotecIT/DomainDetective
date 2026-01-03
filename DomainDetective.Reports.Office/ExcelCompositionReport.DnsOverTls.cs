#if NET8_0
using System;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
#endif

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
#if NET8_0
    private static Action<SheetComposer.ColumnComposer>? BuildDnsOverTlsBlock(DomainBucket bucket)
    {
        if (bucket == null || bucket.DnsOverTls == null)
        {
            return null;
        }

        var dot = bucket.DnsOverTls;
        var projection = DomainDetective.Reports.SectionProjectors.BuildDnsOverTls(dot);
        if (projection == null)
        {
            return null;
        }

        return column =>
        {
            column.Section("DNS over TLS").KeyValues(new (string, object?)[]
            {
                ("Status", dot.Status ?? "-"),
                ("Endpoints", dot.TotalChecked),
                ("Supported", dot.SupportedCount),
                ("Hostname Mismatch", dot.HostnameMismatchCount),
                ("Invalid Cert", dot.InvalidCertificateCount),
                ("Warnings", dot.WarningCount),
                ("Errors", dot.ErrorCount)
            });

            if (projection.Endpoints.Count > 0)
            {
                var rows = projection.Endpoints
                    .Take(200)
                    .Select(e => new
                    {
                        NameServer = e.NameServerHost,
                        Ip = e.ServerIp,
                        e.Port,
                        e.Supported,
                        e.Protocol,
                        e.CipherSuite,
                        HostnameMatch = e.HostnameMatch,
                        CertificateValid = e.CertificateValid,
                        e.Error
                    })
                    .ToList();

                column.TableFrom(rows, title: "Endpoints (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Port"] = "0";
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
