using System.Net;

namespace DomainDetective.Tests;

public class TestDnsPropagationSelection
{
    [Fact]
    public void SelectServersDistributed_DoesNotThrowOnNullLocationOrCountry()
    {
        var servers = new[]
        {
            new PublicDnsEntry
            {
                Enabled = true,
                Country = null,
                Location = null,
                IPAddress = IPAddress.Parse("1.1.1.1"),
                HostName = "one.one.one.one",
                ASN = "13335",
                ASNName = "Cloudflare"
            },
            new PublicDnsEntry
            {
                Enabled = true,
                Country = null,
                Location = null,
                IPAddress = IPAddress.Parse("8.8.8.8"),
                HostName = "dns.google",
                ASN = "15169",
                ASNName = "Google"
            }
        };

        var selected = DomainHealthCheck.SelectServersDistributed(servers, max: 2);

        Assert.Equal(2, selected.Count);
    }
}

