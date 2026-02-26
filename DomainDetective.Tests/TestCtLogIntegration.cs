using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestCtLogIntegration
{
    [Fact]
    public async Task CertificateAnalysisExposesEntries()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[{\"id\":5}]") };
        await analysis.AnalyzeCertificate(cert);
        Assert.True(analysis.PresentInCtLogs);
        Assert.Single(analysis.CtLogEntries);
        Assert.Contains("override", analysis.CtDiscoverySources);
        Assert.Equal(5, analysis.CtLogEntries[0].GetProperty("id").GetInt32());
    }
}
