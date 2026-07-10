using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestSpfHostEvaluator
    {
        [Fact]
        public async Task EvaluateHost_Ip4_Pass()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 ip4:192.0.2.0/24 -all");
            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.10"), "postmaster@example.com", "mail.example.com");
            Assert.Equal("pass", eval.Verdict);
            Assert.Equal("ip4", eval.MatchedType);
            Assert.Contains("ip4:192.0.2.0/24", eval.MatchedToken);
        }

        [Fact]
        public async Task EvaluateHost_All_Softfail()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 ~all");
            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("203.0.113.5"), "postmaster@example.com", "mail.example.com");
            Assert.Equal("softfail", eval.Verdict);
            Assert.Equal("all", eval.MatchedType);
        }

        [Fact]
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
            Assert.Equal(1, eval.DnsLookups);
            Assert.NotNull(eval.Chain);
            Assert.Contains("_spf.inc.test", eval.Chain);
        }

        [Fact]
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

        [Fact]
        public async Task EvaluateHost_RedirectAppliesAfterMechanismsDoNotMatch()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            hc.SpfAnalysis.TestSpfRecords["redirect.example"] = "v=spf1 ip4:203.0.113.0/24 -all";
            await hc.CheckSPF("v=spf1 ip4:192.0.2.0/24 redirect=redirect.example");

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("203.0.113.10"), "postmaster@example.com", "mail.example.com");

            Assert.Equal("pass", eval.Verdict);
            Assert.Equal("ip4", eval.MatchedType);
            Assert.Equal("redirect.example", eval.MatchedDomain);
            Assert.Equal(1, eval.DnsLookups);
            Assert.Contains("redirect.example", eval.Chain);
        }

        [Fact]
        public async Task EvaluateHost_InvalidCidrReturnsPermErrorWithoutThrowing()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 ip4:192.0.2.0/33 -all");

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.10"), "postmaster@example.com", "mail.example.com");

            Assert.Equal("permerror", eval.Verdict);
            Assert.Equal("ip4", eval.MatchedType);
        }

        [Fact]
        public async Task EvaluateHost_AUsesCidrPrefixMatching()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 a:mail.example/24 -all");
            hc.SpfAnalysis.QueryDnsOverride = (name, type) => Task.FromResult(
                name == "mail.example" && type == DnsClientX.DnsRecordType.A
                    ? new[] { new DnsClientX.DnsAnswer { Type = type, DataRaw = "192.0.2.200" } }
                    : System.Array.Empty<DnsClientX.DnsAnswer>());

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.10"), "postmaster@example.com", "mail.example.com");

            Assert.Equal("pass", eval.Verdict);
            Assert.Equal("a", eval.MatchedType);
            Assert.Equal(1, eval.DnsLookups);
        }

        [Fact]
        public async Task EvaluateHost_ExistsQueriesOnlyARecords()
        {
            var queries = new List<DnsClientX.DnsRecordType>();
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 exists:probe.example -all");
            hc.SpfAnalysis.QueryDnsOverride = (name, type) => {
                queries.Add(type);
                return Task.FromResult(type == DnsClientX.DnsRecordType.AAAA
                    ? new[] { new DnsClientX.DnsAnswer { Type = type, DataRaw = "2001:db8::1" } }
                    : System.Array.Empty<DnsClientX.DnsAnswer>());
            };

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.10"), "postmaster@example.com", "mail.example.com");

            Assert.Equal("fail", eval.Verdict);
            Assert.Equal(new[] { DnsClientX.DnsRecordType.A }, queries);
        }

        [Fact]
        public async Task EvaluateHost_IncludeLookupFailureReturnsTempError()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 include:unavailable.example -all");
            hc.SpfAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("simulated DNS timeout");

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.10"), "postmaster@example.com", "mail.example.com");

            Assert.Equal("temperror", eval.Verdict);
            Assert.Equal("include", eval.MatchedType);
        }

        [Fact]
        public async Task EvaluateHost_MultipleIncludedPoliciesReturnPermError()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 include:multiple.example -all");
            hc.SpfAnalysis.QueryDnsOverride = (name, type) => Task.FromResult(
                name == "multiple.example" && type == DnsClientX.DnsRecordType.TXT
                    ? new[] {
                        new DnsClientX.DnsAnswer { Type = type, DataRaw = "v=spf1 ip4:192.0.2.1 -all" },
                        new DnsClientX.DnsAnswer { Type = type, DataRaw = "v=spf1 ip4:192.0.2.2 -all" }
                    }
                    : System.Array.Empty<DnsClientX.DnsAnswer>());

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.1"), "postmaster@example.com", "mail.example.com");

            Assert.Equal("permerror", eval.Verdict);
            Assert.Equal("include", eval.MatchedType);
        }

        [Fact]
        public async Task EvaluateHost_UnknownMechanismReturnsPermError()
        {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 madeup:value -all");

            var eval = await hc.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.1"), "postmaster@example.com", "mail.example.com");

            Assert.Equal("permerror", eval.Verdict);
            Assert.Equal("unknown", eval.MatchedType);
        }
    }
}
