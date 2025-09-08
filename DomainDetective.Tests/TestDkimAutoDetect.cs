using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestDkimAutoDetect
    {
        [Fact]
        public async Task AutoDetect_ParsesKey_And_SetsAdvisory()
        {
            var dns = new DomainDetective.DnsConfiguration();
            dns.QueryDnsOverride = async (name, type) =>
            {
                await Task.CompletedTask;
                if (type != DnsClientX.DnsRecordType.TXT) return System.Array.Empty<DnsClientX.DnsAnswer>();
                if (name == "selector1._domainkey.example.com")
                {
                    // Use a short SPKI-looking base64 that triggers 2048-bit heuristics (starts with MIIBI)
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
            Assert.True(a.ValidPublicKey);
            Assert.True(a.ValidRsaKeyLength);
            Assert.True(a.KeyLength >= 2048);
            Assert.Equal("All DKIM selectors appear valid.", dkim.Advisory);
        }

        [Fact]
        public async Task KeyReuse_Warns()
        {
            var dns = new DomainDetective.DnsConfiguration();
            dns.QueryDnsOverride = async (name, type) =>
            {
                await Task.CompletedTask;
                if (type != DnsClientX.DnsRecordType.TXT) return System.Array.Empty<DnsClientX.DnsAnswer>();
                string rec = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"; // same key for both selectors
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
