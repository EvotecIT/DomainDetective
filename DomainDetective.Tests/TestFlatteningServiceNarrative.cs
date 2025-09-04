using System.Linq;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Tests;

public class TestFlatteningServiceNarrative
{
    [Fact]
    public async Task NarrativeShowsAddressesAndPositiveAdvice()
    {
        var analysis = new FlatteningServiceAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsClientX.DnsRecordType.CNAME)
                {
                    return Task.FromResult(new[] { new DnsClientX.DnsAnswer { DataRaw = "alias.cloudflare.net" } });
                }

                if (type == DnsClientX.DnsRecordType.A)
                {
                    return Task.FromResult(new[] { new DnsClientX.DnsAnswer { DataRaw = "192.0.2.1" } });
                }

                if (type == DnsClientX.DnsRecordType.AAAA)
                {
                    return Task.FromResult(new[] { new DnsClientX.DnsAnswer { DataRaw = "2001:db8::1" } });
                }

                return Task.FromResult(Array.Empty<DnsClientX.DnsAnswer>());
            }
        };

        await analysis.Analyze("example.com", new InternalLogger());
        var sections = FlatteningServiceNarrative.Build(analysis, analysis.Assessments);

        Assert.Contains("alias.cloudflare.net", string.Join(" ", sections.Highlights));
        Assert.Contains("192.0.2.1", string.Join(" ", sections.Highlights));

        var codes = analysis.Recommendations.Select(r => r.Code).ToList();
        Assert.Contains(FlatteningServiceCodes.ResolvedAddresses, codes);
    }
}

