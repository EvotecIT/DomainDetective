using System.IO;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestDnsblLoadFile {
        [Fact]
        public void LoadFileRemovesTrailingComments() {
            var lines = new[] {
                "load1.test # comment",
                "load2.test#",
                "#disabled.test",
                "load3.test ### trailing"
            };
            var file = Path.GetTempFileName();
            File.WriteAllLines(file, lines);

            var analysis = new DNSBLAnalysis();
            analysis.LoadDNSBL(file, clearExisting: true);

            var entries = analysis.GetDNSBL().ToList();
            Assert.Equal(4, entries.Count);
            Assert.Equal("load1.test", entries[0].Domain);
            Assert.Equal("load2.test", entries[1].Domain);
            Assert.Equal("disabled.test", entries[2].Domain);
            Assert.False(entries[2].Enabled);
            Assert.Equal("load3.test", entries[3].Domain);
        }
    }
}