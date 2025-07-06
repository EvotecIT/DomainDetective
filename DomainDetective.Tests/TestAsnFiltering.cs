using System.Linq;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestAsnFiltering {
        [Fact]
        public void GetAsnsReturnsDistinctValues() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var asns = analysis.GetAsns().ToList();
            Assert.NotEmpty(asns);
            Assert.Equal(asns.Count, asns.Distinct().Count());
        }

        [Fact]
        public void FilterByAsnReturnsMatchingServers() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var asn = analysis.Servers.First().ASN;
            var servers = analysis.FilterServers(asn: asn).ToList();
            Assert.NotEmpty(servers);
            Assert.All(servers, s => Assert.Equal(asn, s.ASN));
        }

        [Fact]
        public void FilterByAsnNameReturnsMatchingServers() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var name = analysis.Servers.First(s => !string.IsNullOrWhiteSpace(s.ASNName)).ASNName!;
            var servers = analysis.FilterServers(asnName: name[..3]).ToList();
            Assert.NotEmpty(servers);
            Assert.All(servers, s => Assert.Contains(name[..3], s.ASNName!, System.StringComparison.OrdinalIgnoreCase));
        }
    }
}
