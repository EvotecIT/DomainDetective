using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDnssecAdMultiResolver
{
    [Fact]
    public async Task MultiResolverAd_InfoLogged_WhenTwoResolversConfirm()
    {
        var analysis = new DnsSecAnalysis();
        var logger = new InternalLogger();

        // Simulate Cloudflare+Google = AD=true, Quad9 = AD=false
        analysis.AdProbeOverride = (ep, domain, ct) =>
        {
            bool ad = ep == DnsClientX.DnsEndpoint.Cloudflare || ep == DnsClientX.DnsEndpoint.Google;
            return Task.FromResult((ok: true, ad: ad));
        };

        await analysis.MultiResolverAdCheck("example.com", logger, CancellationToken.None);

        Assert.Contains(analysis.Assessments, a => a.Code == DnssecCodes.AuthenticDataMultiResolver);
    }
}

