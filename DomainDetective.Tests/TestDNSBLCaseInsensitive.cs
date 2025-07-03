using System.Linq;

namespace DomainDetective.Tests {
    public class TestDnsblCaseInsensitive {
        [Fact]
        public void AddDnsblDoesNotAddCaseInsensitiveDuplicates() {
            var analysis = new DNSBLAnalysis();
            var before = analysis.GetDNSBL().Count;

            analysis.AddDNSBL("Case.Test");
            analysis.AddDNSBL("case.test");

            var entries = analysis
                .GetDNSBL()
                .Where(e => string.Equals(e.Domain, "case.test", StringComparison.OrdinalIgnoreCase))
                .ToList();

            Assert.Single(entries);
            Assert.Equal(before + 1, analysis.GetDNSBL().Count);
        }

        [Fact]
        public void AddDnsblStoresLowercaseDomain() {
            var analysis = new DNSBLAnalysis();
            analysis.ClearDNSBL();

            analysis.AddDNSBL("MiXeD.Case");

            var entry = Assert.Single(analysis.GetDNSBL());
            Assert.Equal("mixed.case", entry.Domain);
        }

        [Fact]
        public void RemoveDnsblIsCaseInsensitive() {
            var analysis = new DNSBLAnalysis();
            analysis.ClearDNSBL();

            analysis.AddDNSBL("remove.test");
            analysis.RemoveDNSBL("ReMoVe.TeSt");

            Assert.Empty(analysis.GetDNSBL());
        }
    }
}