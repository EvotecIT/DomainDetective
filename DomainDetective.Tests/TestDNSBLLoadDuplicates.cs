using System.IO;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestDnsblLoadDuplicates {
        [Fact]
        public void LoadFileSkipsDuplicateEntries() {
            var lines = new[] {
                "duplicate.test",
                "duplicate.test",
                "unique.test"
            };
            var file = Path.GetTempFileName();
            try {
                File.WriteAllLines(file, lines);

                var analysis = new DNSBLAnalysis();
                analysis.LoadDNSBL(file, clearExisting: true);

                var duplicates = analysis.GetDNSBL()
                    .Where(e => e.Domain == "duplicate.test")
                    .ToList();
                Assert.Single(duplicates);
                Assert.Contains(analysis.GetDNSBL(), e => e.Domain == "unique.test");
            } finally {
                File.Delete(file);
            }
        }
    }
}
