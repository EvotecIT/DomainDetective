using DnsClientX;
using System.Threading.Tasks;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestSmimeaNarrative {
    [Fact]
    public async Task NarrativeSummarizesRecords() {
        var record = "3 1 1 " + new string('A', 64);
        var analysis = new SMIMEAAnalysis { Subject = "user@example.com" };
        await analysis.AnalyzeSMIMEARecords(new[] { new DnsAnswer { DataRaw = record } }, new InternalLogger());
        var sections = SmimeaNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("SMIMEA record"));
        Assert.Contains(sections.Positives, p => p.Contains("SMIMEA record present"));
    }
}

