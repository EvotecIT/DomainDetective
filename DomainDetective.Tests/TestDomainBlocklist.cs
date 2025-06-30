using DomainDetective;
using DnsClientX;

namespace DomainDetective.Tests {
    public class TestDomainBlocklist {
        [Fact(Skip="Requires network")]
        public async Task ListedDomainsReturnPositive() {
            var analysis = new DNSBLAnalysis {
                DnsConfiguration = new DnsConfiguration { DnsEndpoint = DnsEndpoint.System }
            };
            analysis.ClearDNSBL();
            analysis.AddDNSBL("multi.uribl.com");
            analysis.AddDNSBL("dbl.spamhaus.org");

            await analysis.IsDomainListedAsync("dbltest.com", new InternalLogger());
            var resultSpamhaus = analysis.Results["dbltest.com"];
            Assert.Contains("dbl.spamhaus.org", resultSpamhaus.ListedBlacklist);
            Assert.True(resultSpamhaus.IsBlacklisted);

            await analysis.IsDomainListedAsync("test.uribl.com", new InternalLogger());
            var resultUribl = analysis.Results["test.uribl.com"];
            Assert.Contains("multi.uribl.com", resultUribl.ListedBlacklist);
            Assert.True(resultUribl.IsBlacklisted);
        }

        [Fact(Skip="Requires network")]
        public async Task UnlistedDomainReturnsNegative() {
            var analysis = new DNSBLAnalysis {
                DnsConfiguration = new DnsConfiguration { DnsEndpoint = DnsEndpoint.System }
            };
            analysis.ClearDNSBL();
            analysis.AddDNSBL("multi.uribl.com");
            analysis.AddDNSBL("dbl.spamhaus.org");

            var listed = await analysis.IsDomainListedAsync("example.com", new InternalLogger());
            Assert.False(listed);
        }
    }
}
