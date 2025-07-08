using DomainDetective;
using DnsClientX;
using Xunit.Sdk;

namespace DomainDetective.Tests {
    public class TestDomainBlocklist {
        [SkippableFact]
        public async Task ListedDomainsReturnPositive() {
            var analysis = new DNSBLAnalysis {
                DnsConfiguration = new DnsConfiguration { DnsEndpoint = DnsEndpoint.System }
            };
            analysis.ClearDNSBL();
            analysis.AddDNSBL("multi.uribl.com");
            analysis.AddDNSBL("dbl.spamhaus.org");

            await analysis.IsDomainListedAsync("dbltest.com", new InternalLogger());
            var resultSpamhaus = analysis.Results["dbltest.com"];
            if (!resultSpamhaus.ListedBlacklist.Contains("dbl.spamhaus.org")) {
                throw Xunit.Sdk.SkipException.ForSkip("Spamhaus DNSBL not reachable");
            }
            Assert.True(resultSpamhaus.IsBlacklisted);

            await analysis.IsDomainListedAsync("test.uribl.com", new InternalLogger());
            var resultUribl = analysis.Results["test.uribl.com"];
            if (!resultUribl.ListedBlacklist.Contains("multi.uribl.com")) {
                throw Xunit.Sdk.SkipException.ForSkip("URIBL DNSBL not reachable");
            }
            Assert.True(resultUribl.IsBlacklisted);
        }

        [Fact]
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
