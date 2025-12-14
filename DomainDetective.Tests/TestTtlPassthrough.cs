using DnsClientX;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestTtlPassthrough {
        [Fact]
        public async Task SpfAnalysis_CapturesDnsRecordTtl() {
            var spf = new SpfAnalysis { Subject = "example.com" };
            await spf.AnalyzeSpfRecords(new[] {
                new DnsAnswer { Type = DnsRecordType.TXT, TTL = 3600, DataRaw = "v=spf1 -all" }
            }, new InternalLogger());

            Assert.Equal(3600, spf.DnsRecordTtl);

            var view = DomainDetective.Views.Converters.Convert(spf);
            Assert.Equal(3600, view.DnsRecordTtl);
        }

        [Fact]
        public async Task DmarcAnalysis_CapturesDnsRecordTtl() {
            var dmarc = new DmarcAnalysis { Subject = "example.com" };
            await dmarc.AnalyzeDmarcRecords(
                new[] { new DnsAnswer { Type = DnsRecordType.TXT, TTL = 7200, DataRaw = "v=DMARC1; p=none; rua=mailto:dmarc@example.com" } },
                new InternalLogger(),
                domainName: "example.com",
                getOrgDomain: _ => "example.com");

            Assert.Equal(7200, dmarc.DnsRecordTtl);

            var view = DomainDetective.Views.Converters.Convert(dmarc);
            Assert.Equal(7200, view.DnsRecordTtl);
        }

        [Fact]
        public async Task DkimAnalysis_CapturesPerSelectorDnsRecordTtl_AndFlowsToReports() {
            var dkim = new DkimAnalysis { Subject = "example.com" };
            await dkim.AnalyzeDkimRecords("s1", new[] {
                new DnsAnswer { Type = DnsRecordType.TXT, TTL = 300, Name = "s1._domainkey.example.com", DataRaw = "v=DKIM1; p=dGVzdA==" }
            }, new InternalLogger());

            Assert.True(dkim.AnalysisResults.TryGetValue("s1", out var res));
            Assert.Equal(300, res.DnsRecordTtl);

            var viewList = DomainDetective.Views.Converters.Convert(dkim).ToList();
            var view = viewList.Single(v => v.Selector == "s1");
            Assert.Equal(300, view.DnsRecordTtl);

            var sec = DomainDetective.Reports.SectionProjectors.BuildDkim(viewList);
            Assert.NotNull(sec);
            Assert.Equal(300, sec!.Rows.Single(r => r.Selector == "s1").TtlSeconds);
        }

        [Fact]
        public async Task MxAnalysis_CapturesMxTtls() {
            var mx = new MXAnalysis { Subject = "example.com" };
            mx.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());

            await mx.AnalyzeMxRecords(new[] {
                new DnsAnswer { Type = DnsRecordType.MX, TTL = 600, DataRaw = "10 mx1.example.com." },
                new DnsAnswer { Type = DnsRecordType.MX, TTL = 600, DataRaw = "20 mx2.example.com." }
            }, new InternalLogger());

            Assert.Equal(new[] { 600, 600 }, mx.MxRecordTtls.ToArray());
            Assert.Equal(600, mx.MinMxTtl);
            Assert.Equal(600, mx.MaxMxTtl);

            var view = DomainDetective.Views.Converters.Convert(mx);
            Assert.Equal(600, view.MinMxTtl);
        }

        [Fact]
        public async Task MtastsAnalysis_CapturesDnsRecordTtl_WithoutFetchingPolicy() {
            var mtasts = new MTASTSAnalysis {
                QueryDnsOverride = (_, _) => Task.FromResult(new[] {
                    new DnsAnswer { Type = DnsRecordType.TXT, TTL = 1800, DataRaw = "invalid" }
                })
            };

            await mtasts.AnalyzePolicy("example.com", new InternalLogger());

            Assert.Equal(1800, mtasts.DnsRecordTtl);

            var view = DomainDetective.Views.Converters.Convert(mtasts);
            Assert.Equal(1800, view.DnsRecordTtl);
        }

        [Fact]
        public async Task TlsRptAnalysis_CapturesDnsRecordTtl() {
            var tlsrpt = new TLSRPTAnalysis { Subject = "example.com" };
            await tlsrpt.AnalyzeTlsRptRecords(new[] {
                new DnsAnswer { Type = DnsRecordType.TXT, TTL = 900, DataRaw = "v=TLSRPTv1; rua=mailto:tlsrpt@example.com" }
            }, new InternalLogger());

            Assert.Equal(900, tlsrpt.DnsRecordTtl);

            var view = DomainDetective.Views.Converters.Convert(tlsrpt);
            Assert.Equal(900, view.DnsRecordTtl);
        }
    }
}
