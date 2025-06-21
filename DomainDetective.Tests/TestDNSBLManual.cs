namespace DomainDetective.Tests {
    public class TestDnsblManual {
        [Fact]
        public void AddDnsblAddsEntry() {
            var analysis = new DNSBLAnalysis();
            var before = analysis.GetDNSBL().Count;

            analysis.AddDNSBL("manual.test");

            Assert.Equal(before + 1, analysis.GetDNSBL().Count);
            Assert.Contains(analysis.GetDNSBL(), e => e.Domain == "manual.test");
        }

        [Fact]
        public void RemoveDnsblRemovesEntry() {
            var analysis = new DNSBLAnalysis();

            analysis.AddDNSBL("remove.test");
            Assert.Contains(analysis.GetDNSBL(), e => e.Domain == "remove.test");

            analysis.RemoveDNSBL("remove.test");

            Assert.DoesNotContain(analysis.GetDNSBL(), e => e.Domain == "remove.test");
        }

        [Fact]
        public void ClearDnsblEmptiesList() {
            var analysis = new DNSBLAnalysis();

            Assert.NotEmpty(analysis.GetDNSBL());

            analysis.ClearDNSBL();

            Assert.Empty(analysis.GetDNSBL());
        }
    }
}
