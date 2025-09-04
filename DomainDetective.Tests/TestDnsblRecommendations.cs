using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsblRecommendations
{
    [Fact]
    public async Task EmitsPositiveRecommendations()
    {
        var analysis = new DNSBLAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsFullOverride = (names, _) =>
            {
                var responses = new List<DnsResponse>();
                foreach (var name in names)
                {
                    responses.Add(new DnsResponse { Answers = System.Array.Empty<DnsAnswer>() });
                }
                return Task.FromResult<IEnumerable<DnsResponse>>(responses);
            }
        };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("example.test");

        await foreach (var _ in analysis.AnalyzeDNSBLRecords("1.2.3.4", new InternalLogger()))
        {
        }

        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == DnsblCodes.NotListed);
    }
}

