using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using DomainDetective;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestSubdomainEnumeration
{
    [Fact]
    public async Task EnumeratesSubdomains()
    {
        var enumr = new SubdomainEnumeration
        {
            QueryDnsOverride = (name, type) =>
            {
                if (name == "www.example.com")
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                }
                return Task.FromResult(System.Array.Empty<DnsAnswer>());
            },
            PassiveLookupOverride = (domain, ct) => Task.FromResult<IEnumerable<string>>(new[] { "mail.example.com" })
        };

        await enumr.Enumerate("example.com", new InternalLogger());

        Assert.Contains("www.example.com", enumr.BruteForceResults);
        Assert.Contains("mail.example.com", enumr.PassiveResults);
    }

    [Fact]
    public async Task UsesCertSpotterFallbackWhenCrtShFails()
    {
        const string certSpotterJson = @"
[
  { ""id"": ""12345"", ""dns_names"": [""api.example.com"", ""example.com""] }
]";

        var enumr = new SubdomainEnumeration
        {
            Dictionary = { },
            PassiveHttpGetOverride = (url, _) =>
            {
                if (url.Contains("crt.sh", System.StringComparison.OrdinalIgnoreCase))
                {
                    throw new HttpRequestException("Simulated crt.sh outage.");
                }

                return Task.FromResult(certSpotterJson);
            }
        };

        await enumr.Enumerate("example.com", new InternalLogger());

        Assert.Contains("api.example.com", enumr.PassiveResults);
        Assert.Contains("example.com", enumr.PassiveResults);
        Assert.Equal(2, enumr.PassiveResults.Distinct(System.StringComparer.OrdinalIgnoreCase).Count());
    }
}
