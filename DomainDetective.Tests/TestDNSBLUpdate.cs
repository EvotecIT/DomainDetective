namespace DomainDetective.Tests {
    public class TestDnsblUpdate {
        [Fact]
        public void AddDnsblUpdatesExistingEntry() {
            var analysis = new DNSBLAnalysis();
            analysis.ClearDNSBL();

            analysis.AddDNSBL("update.test", enabled: false, comment: "first");
            analysis.AddDNSBL("update.test", enabled: true, comment: "second");

            var entry = analysis.GetDNSBL().Single(e => e.Domain == "update.test");
            Assert.True(entry.Enabled);
            Assert.Equal("second", entry.Comment);
        }
    }
}
