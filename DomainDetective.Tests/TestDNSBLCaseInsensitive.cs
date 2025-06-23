using System.Linq;

namespace DomainDetective.Tests {
    public class TestDnsblCaseInsensitive {
        [Fact]
        public void AddDnsblDoesNotAddCaseInsensitiveDuplicates() {
            var analysis = new DNSBLAnalysis();
            var before = analysis.GetDNSBL().Count;

            analysis.AddDNSBL("Case.Test");
            analysis.AddDNSBL("case.test");

            var entries = analysis.GetDNSBL().Where(e => e.Domain == "case.test").ToList();
            Assert.Single(entries);
            Assert.Equal(before + 1, analysis.GetDNSBL().Count);
        }
    }
}
