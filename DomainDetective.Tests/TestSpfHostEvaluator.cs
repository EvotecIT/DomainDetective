using System;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestSpfHostEvaluator
    {
        [Fact(Skip="Pending fine-tuning; skip in CI for now")]
        public async Task EvaluateHost_Ip4_Pass()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 ip4:192.0.2.0/24 -all");
            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.10"), "postmaster@example.com", "mail.example.com");
            Assert.Equal("pass", eval.Verdict);
            Assert.Equal("ip4", eval.MatchedType);
            Assert.Contains("ip4:192.0.2.0/24", eval.MatchedToken);
        }

        [Fact(Skip="Pending fine-tuning; skip in CI for now")]
        public async Task EvaluateHost_All_Softfail()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 ~all");
            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("203.0.113.5"), "postmaster@example.com", "mail.example.com");
            Assert.Equal("softfail", eval.Verdict);
            Assert.Equal("all", eval.MatchedType);
        }

        [Fact(Skip="Pending fine-tuning; skip in CI for now")]
        public async Task EvaluateHost_Include_Chain_Pass()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 include:_spf.inc.test -all");
            hc.DnsConfiguration.QueryDnsOverride = async (name, type) =>
            {
                await Task.CompletedTask;
                if (type == DnsClientX.DnsRecordType.TXT && name == "_spf.inc.test")
                {
                    return new []
                    {
                        new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.TXT, DataRaw = "v=spf1 ip4:203.0.113.10 -all" }
                    };
                }
                return System.Array.Empty<DnsClientX.DnsAnswer>();
            };
            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("203.0.113.10"), "postmaster@example.com", "mail.example.com");
            Assert.Equal("pass", eval.Verdict);
            Assert.Equal("include", eval.MatchedType);
            Assert.NotNull(eval.Chain);
            Assert.Contains("_spf.inc.test", eval.Chain);
        }

        [Fact(Skip="Pending fine-tuning; skip in CI for now")]
        public async Task EvaluateHost_LookupsExceeded_PermError()        
        {
            var hc = new DomainDetective.DomainHealthCheck();
            // 11 'a:' mechanisms to drive lookup counter over 10
            await hc.CheckSPF("v=spf1 a:a1.example a:a2.example a:a3.example a:a4.example a:a5.example a:a6.example a:a7.example a:a8.example a:a9.example a:a10.example a:a11.example -all");
            hc.DnsConfiguration.QueryDnsOverride = (name, type) => Task.FromResult(System.Array.Empty<DnsClientX.DnsAnswer>());
            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("198.51.100.20"), "postmaster@example.com", "mail.example.com");
            Assert.True(eval.LookupsExceeded);
            Assert.Equal("permerror", eval.Verdict);
        }

        [Fact]
        public async Task EvaluateHost_SpfTxtWithCnameFirst_PicksTxt()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            hc.DnsConfiguration.QueryDnsOverride = (name, type) =>
            {
                if (type == DnsClientX.DnsRecordType.TXT && string.Equals(name, "example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(new[]
                    {
                        new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.CNAME, DataRaw = "alias.example.net." },
                        new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.TXT, DataRaw = "v=spf1 -all" }
                    });
                }

                return Task.FromResult(System.Array.Empty<DnsClientX.DnsAnswer>());
            };

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.10"), "postmaster@example.com", "mail.example.com");
            Assert.Equal("fail", eval.Verdict);
            Assert.Equal("all", eval.MatchedType);
        }
    }
}
