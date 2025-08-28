using System;
using System.Reflection;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestWhoisMetadata {
        [Fact]
        public async Task IanaFallbackSetsLookupSourceAndServer() {
            var analysis = new DomainDetective.WhoisAnalysis();
            // Force DNS discovery to fail by providing an override returning empty
            analysis.DnsConfiguration.QueryDnsOverride = (name, type) => Task.FromResult(Array.Empty<DnsClientX.DnsAnswer>());
            // Provide IANA HTML with whois server
            analysis.IanaQueryOverride = async (tld) => await Task.FromResult("<pre>whois: whois.example.test</pre>");

            // Call GetWhoisServer via reflection to avoid network connect
            var mi = typeof(DomainDetective.WhoisAnalysis).GetMethod("GetWhoisServer", BindingFlags.NonPublic | BindingFlags.Instance);
            var task = (Task<string?>)mi.Invoke(analysis, new object[] { "example.zz" });
            var server = await task;

            Assert.Equal("whois.example.test", server);
            Assert.Equal("IANA", analysis.WhoisLookupSource);
            Assert.Equal("whois.example.test", analysis.WhoisServerUsed);
        }
    }
}

