using System.Text.Json;

namespace DomainDetective.Tests;

public class TestRdapModels
{
    [Fact]
    public void DomainSerializationRoundTrip()
    {
        const string json = "{\"ldhName\":\"example.com\",\"nameservers\":[{\"ldhName\":\"ns1.example.net\"},{\"ldhName\":\"ns2.example.net\"}],\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2000-01-01T00:00:00Z\"},{\"eventAction\":\"expiration\",\"eventDate\":\"2030-01-01T00:00:00Z\"}],\"entities\":[{\"handle\":\"123\",\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"fn\",{},\"text\",\"Registrar Inc\"]]]}]}";

        var domain = JsonSerializer.Deserialize<RdapDomain>(json, RdapJson.Options)!;
        Assert.Equal("example.com", domain.LdhName);
        Assert.Equal("ns1.example.net", domain.Nameservers[0].LdhName);
        Assert.Equal(RdapEventAction.Registration, domain.Events[0].Action);

        var serialized = JsonSerializer.Serialize(domain, RdapJson.Options);
        var round = JsonSerializer.Deserialize<RdapDomain>(serialized, RdapJson.Options)!;
        Assert.Equal(domain.LdhName, round.LdhName);
        Assert.Equal(domain.Nameservers[1].LdhName, round.Nameservers[1].LdhName);
    }
}
