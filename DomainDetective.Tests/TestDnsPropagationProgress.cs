using DnsClientX;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDnsPropagationProgress {
    [Fact]
    public async Task ProgressCompletesWhenNoServers() {
        var analysis = new DnsPropagationAnalysis();
        var values = new List<double>();
        var progress = new Progress<double>(v => values.Add(v));
        var results = await analysis.QueryAsync("example.com", DnsRecordType.A, Enumerable.Empty<PublicDnsEntry>(), progress: progress);
        Assert.Empty(results);
        if (values.Count > 0) {
            Assert.Contains(100, values.Select(v => (int)v));
        }
    }
}
