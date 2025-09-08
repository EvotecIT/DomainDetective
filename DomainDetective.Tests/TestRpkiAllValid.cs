using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestRpkiAllValid
{
    [Fact]
    public async Task EmitsAllValidPositiveWhenAllIpsValid()
    {
        var analysis = new RPKIAnalysis
        {
            QueryDnsOverride = (name, type) => type switch
            {
                DnsRecordType.A => Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "198.51.100.10" } }),
                DnsRecordType.AAAA => Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.AAAA, DataRaw = "2001:db8::10" } }),
                _ => Task.FromResult(System.Array.Empty<DnsAnswer>())
            },
            QueryRpkiOverride = ip => Task.FromResult(("198.51.100.0/24", 64512, true))
        };

        var logger = new InternalLogger();
        await analysis.Analyze("example.com", logger);

        Assert.True(analysis.AllValid);
        Assert.Contains(analysis.Assessments, a => a.Severity == AssessmentSeverity.Info && a.Code == RpkiCodes.AllValid);
    }
}

