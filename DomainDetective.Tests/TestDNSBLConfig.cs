namespace DomainDetective.Tests {
    public class TestDnsblConfig {
        [Fact]
        public void LoadConfigWithClear() {
            var json = "{\"providers\":[{\"domain\":\"test.example\"},{\"domain\":\"another.test\",\"enabled\":false}]}";
            var file = Path.GetTempFileName();
            File.WriteAllText(file, json);

            var analysis = new DNSBLAnalysis();
            analysis.LoadDnsblConfig(file, clearExisting: true);

            var entries = analysis.GetDNSBL().ToList();
            Assert.Equal(2, entries.Count);
            Assert.Contains(entries, e => e.Domain == "test.example");
            Assert.Contains(entries, e => e.Domain == "another.test" && !e.Enabled);
        }

        [Fact]
        public void LoadConfigAddsMissing() {
            var json = "{\"providers\":[{\"domain\":\"added.test\"}]}";
            var file = Path.GetTempFileName();
            File.WriteAllText(file, json);

            var analysis = new DNSBLAnalysis();
            var before = analysis.GetDNSBL().Count;
            analysis.LoadDnsblConfig(file);
            var after = analysis.GetDNSBL().Count;

            Assert.Equal(before + 1, after);
            Assert.Contains(analysis.GetDNSBL(), e => e.Domain == "added.test");
        }
    }
}
