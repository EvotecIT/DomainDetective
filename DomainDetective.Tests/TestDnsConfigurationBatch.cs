using System.Threading.Tasks;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsConfigurationBatch
{
    [Fact]
    public async Task QueryDNSBatch_PreservesInputOrder()
    {
        var cfg = new DnsConfiguration
        {
            QueryDnsOverride = (name, recordType) =>
            {
                var answer = new DnsAnswer
                {
                    Name = name,
                    Type = recordType,
                    TTL = 60,
                    DataRaw = name.StartsWith("a", System.StringComparison.OrdinalIgnoreCase) ? "1.1.1.1" : "2.2.2.2"
                };
                return Task.FromResult(new[] { answer });
            }
        };

        var names = new[] { "a.example.com", "b.example.com", "a2.example.com" };
        var results = await cfg.QueryDNSBatch(names, DnsRecordType.A);

        Assert.Equal(names.Length, results.Count);
        Assert.Equal(names[0], results[0].Name);
        Assert.Equal(names[1], results[1].Name);
        Assert.Equal(names[2], results[2].Name);

        Assert.True(results[0].QuerySucceeded);
        Assert.True(results[1].QuerySucceeded);
        Assert.True(results[2].QuerySucceeded);

        Assert.Equal(DnsResponseCode.NoError, results[0].ResponseCode);
        Assert.Equal("1.1.1.1", results[0].Answers[0].DataRaw);
        Assert.Equal("2.2.2.2", results[1].Answers[0].DataRaw);
        Assert.Equal("1.1.1.1", results[2].Answers[0].DataRaw);
    }
}
