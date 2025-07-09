using System.Linq;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestDnsServerQuery {
        [Fact]
        public void BuilderFiltersByCountry() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var query = DnsServerQuery.Create().FromCountry("Poland");
            var servers = analysis.FilterServers(query).ToList();
            Assert.NotEmpty(servers);
            Assert.All(servers, s => Assert.Equal("Poland", s.Country));
        }

        [Fact]
        public void BuilderTakeLimitsResults() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var query = DnsServerQuery.Create().Take(3);
            var servers = analysis.FilterServers(query).ToList();
            Assert.Equal(3, servers.Count);
        }

        [Fact]
        public void BuilderSupportsMultipleFilters() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var query = DnsServerQuery.Create().FromCountry("Poland").Take(2);
            var servers = analysis.FilterServers(query).ToList();
            Assert.True(servers.Count <= 2);
            Assert.All(servers, s => Assert.Equal("Poland", s.Country));
        }

        [Fact]
        public void BuilderIsCaseInsensitive() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var query = DnsServerQuery.Create().FromCountry("poland");
            var servers = analysis.FilterServers(query).ToList();
            Assert.NotEmpty(servers);
            Assert.All(servers, s => Assert.Equal("Poland", s.Country));
        }
    }
}
