using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDnsblUpdateConcurrency {
        [Fact]
        public async Task LoadDnsblConfigConcurrent() {
            var json = "{\"providers\":[{\"domain\":\"concurrent.test\"}],\"domainBlockLists\":[{\"domain\":\"dbl.test\"}],\"ipBlockLists\":[{\"name\":\"drop\",\"url\":\"http://example.com/drop.txt\"}]}"; 
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);
                var analysis = new DNSBLAnalysis();
                var tasks = Enumerable.Range(0, 20)
                    .Select(_ => Task.Run(() => analysis.LoadDnsblConfig(file, overwriteExisting: true, clearExisting: true)));
                await Task.WhenAll(tasks);
                Assert.Single(analysis.GetDNSBL());
                Assert.Single(analysis.DomainDNSBLLists);
                Assert.Single(analysis.GetIpBlockLists());
            } finally {
                File.Delete(file);
            }
        }
    }
}
