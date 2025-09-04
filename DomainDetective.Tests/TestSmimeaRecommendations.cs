using DnsClientX;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestSmimeaRecommendations {
    [Fact]
    public async Task EmitsPositiveRecommendations() {
        var record = "3 1 1 " + new string('A', 64);
        var analysis = new SMIMEAAnalysis();
        await analysis.AnalyzeSMIMEARecords(new[] { new DnsAnswer { DataRaw = record } }, new InternalLogger());
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == SmimeaCodes.RecordPresent);
        Assert.Contains(positives, p => p.Code == SmimeaCodes.CertificateValid);
    }
}

