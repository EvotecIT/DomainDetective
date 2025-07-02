using System.Collections.Generic;
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
}
