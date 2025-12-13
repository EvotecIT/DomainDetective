using System;
using System.Collections.Generic;
using System.Linq;
#if NET8_0
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
#endif

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
#if NET8_0
    private static void BuildMatrixSheet(ExcelDocument doc, List<KeyValuePair<string, DomainBucket>> domains)
    {
        try
        {
            var mx = new SheetComposer(doc, "Matrix");
            mx.Title("Status Matrix");
            var matrix = new List<object>();
            foreach (var kv in domains)
            {
                var b = kv.Value; string dom = kv.Key;
                string dkim = b.Dkim.Count>0 ? (b.Dkim.Max(x=>x.Status) ?? "-") : "-";
                matrix.Add(new {
                    Domain = dom,
                    MX = b.Mx?.Status ?? "-",
                    SPF = b.Spf?.Status ?? "-",
                    DKIM = dkim,
                    DMARC = b.Dmarc?.Status ?? "-",
                    MTASTS = b.Mtasts?.Status ?? "-",
                    TLSRPT = b.TlsRpt?.Status ?? "-",
                    DNSBL = b.Dnsbl?.Status ?? "-",
                    NS = b.Ns?.Status ?? "-",
                    SOA = b.Soa?.Status ?? "-",
                    CAA = b.Caa?.Status ?? "-",
                    RPKI = b.Rpki?.Status ?? "-"
                });
            }
            mx.TableFrom(matrix, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                var ok = "#D1E7DD"; var warn = "#FFF4CE"; var err = "#F8D7DA"; var none = "#E9ECEF";
                foreach (var col in new[]{"MX","SPF","DKIM","DMARC","MTASTS","TLSRPT","DNSBL","NS","SOA","CAA","RPKI"})
                {
                    v.TextBackgrounds[col] = new System.Collections.Generic.Dictionary<string,string>(System.StringComparer.OrdinalIgnoreCase) {
                        {"OK", ok},{"Pass", ok},{"Valid", ok},{"Warning", warn},{"Warn", warn},{"Error", err},{"Fail", err},{"-", none},{"None", none},{"Missing", none}
                    };
                }
                v.FreezeHeaderRow = true;
            });
            mx.Finish(autoFitColumns: true);
        }
        catch { }
    }
#endif
}

