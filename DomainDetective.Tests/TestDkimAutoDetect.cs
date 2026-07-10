using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests
{
public class TestDkimAutoDetect
{
        [Fact]
        public async Task ExplicitSelectorQueriesUseBoundedConcurrency()
        {
            var current = 0;
            var maximum = 0;
            var healthCheck = new DomainDetective.DomainHealthCheck();
            healthCheck.DKIMAnalysis.SelectorQueryConcurrency = 4;
            healthCheck.DnsConfiguration.QueryDnsOverride = async (name, _) =>
            {
                if (name.StartsWith("_adsp.", StringComparison.OrdinalIgnoreCase))
                {
                    return Array.Empty<DnsClientX.DnsAnswer>();
                }

                var active = Interlocked.Increment(ref current);
                var observed = Volatile.Read(ref maximum);
                while (active > observed)
                {
                    Interlocked.CompareExchange(ref maximum, active, observed);
                    observed = Volatile.Read(ref maximum);
                }
                await Task.Delay(25);
                Interlocked.Decrement(ref current);
                return Array.Empty<DnsClientX.DnsAnswer>();
            };

            await healthCheck.VerifyDKIM("example.com", Enumerable.Range(0, 16).Select(i => "selector" + i).ToArray());

            Assert.InRange(maximum, 2, 4);
        }

        [Fact]
        public async Task AutoDetect_RejectsTruncatedSpkiKey()
        {
            var dns = new DomainDetective.DnsConfiguration();
            dns.QueryDnsOverride = async (name, type) =>
            {
                await Task.CompletedTask;
                if (type != DnsClientX.DnsRecordType.TXT) return System.Array.Empty<DnsClientX.DnsAnswer>();
                if (name == "selector1._domainkey.example.com")
                {
                    // The DER header is recognizable, but the key is deliberately truncated.
                    var rec = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A";
                    return new[] { new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.TXT, DataRaw = rec } };
                }
                // emulate built-in selector list hit
                if (name.EndsWith("._domainkey.example.com"))
                {
                    // only selector1 exists
                    return System.Array.Empty<DnsClientX.DnsAnswer>();
                }
                return System.Array.Empty<DnsClientX.DnsAnswer>();
            };

            var logger = new DomainDetective.InternalLogger(false);
            var dkim = new DomainDetective.DkimAnalysis();
            var found = await dkim.QueryWellKnownSelectors("example.com", dns, logger);
            Assert.Equal("selector1", found);
            Assert.True(dkim.AnalysisResults.ContainsKey("selector1"));
            var a = dkim.AnalysisResults["selector1"];
            Assert.False(a.ValidPublicKey);
            Assert.False(a.ValidRsaKeyLength);
            Assert.False(a.ValidKeyLength);
            Assert.Equal("Issues detected with selector(s): selector1.", dkim.Advisory);
        }

        [Fact]
        public async Task KeyReuse_Warns()
        {
            var dns = new DomainDetective.DnsConfiguration();
            dns.QueryDnsOverride = async (name, type) =>
            {
                await Task.CompletedTask;
                if (type != DnsClientX.DnsRecordType.TXT) return System.Array.Empty<DnsClientX.DnsAnswer>();
                const string rec = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA21OfspkRgPHhdCgu3kWgBX+xLyw7wRqM+Y4KaX82Pul9ikEDfZCJ35siFzV2WMH9Od/yM2TtMnubRqm9QN6paEB0VhNgNURQMmyTVsBO1usTJS9IvkIt3JtTFEinzVJLEaOC/F3d6bJaW9MMKUTBra9RcUf/E6dWAaJX8lrK8SefL9adNTwED8ZgFBnFcoJJn6e1W2WyIZ/8XAk+5Jwc7JMFZsdjFYdBSDPNyEfhNsKahVdRvdCG+OeDHyLSiNuFE27wtXaUI2TySDcfSSzE8k8z/Td9mMb0DQ2qaJ6xxk/5cwzwYSXr3sdGp++mHpGOJm18OwfsJmFCuSEcFGrHAQIDAQAB";
                if (name == "s1._domainkey.example.com" || name == "s2._domainkey.example.com")
                {
                    return new[] { new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.TXT, DataRaw = rec } };
                }
                return System.Array.Empty<DnsClientX.DnsAnswer>();
            };

            var logger = new DomainDetective.InternalLogger(false);
            var dkim = new DomainDetective.DkimAnalysis();
            // Manually analyze two selectors
            var s1 = await dns.QueryDNS("s1._domainkey.example.com", DnsClientX.DnsRecordType.TXT);
            await dkim.AnalyzeDkimRecords("s1", s1, logger);
            var s2 = await dns.QueryDNS("s2._domainkey.example.com", DnsClientX.DnsRecordType.TXT);
            await dkim.AnalyzeDkimRecords("s2", s2, logger);

            // Expect a key reuse warning assessment
            Assert.Contains(dkim.Assessments, a => a?.Code == DomainDetective.DkimCodes.KeyReused);
        }
    }
}
