using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Tests;

public class TestRdapNarrative
{
    [Fact]
    public async Task RdapNarrativeSummarizesFields()
    {
        RdapAnalysis.ClearCache();
        const string json = "{\"ldhName\":\"example.com\",\"status\":[\"active\"],\"nameservers\":[{\"ldhName\":\"ns1.example.net\"},{\"ldhName\":\"ns2.example.net\"}],\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2000-01-01T00:00:00Z\"},{\"eventAction\":\"expiration\",\"eventDate\":\"2030-01-01T00:00:00Z\"}],\"entities\":[{\"handle\":\"123\",\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"fn\",{},\"text\",\"Registrar Inc\"],[\"email\",{},\"text\",\"admin@example.com\"]]]}]}";
        var analysis = new RdapAnalysis { QueryOverride = _ => Task.FromResult(json) };
        await analysis.Analyze("example.com", new InternalLogger());
        var sections = RdapNarrative.Build(analysis);
        Assert.Contains("Registered on 2000-01-01T00:00:00Z", sections.Highlights);
        Assert.Contains("Expires on 2030-01-01T00:00:00Z", sections.Highlights);
        Assert.Contains("Registrar: Registrar Inc", sections.Highlights);
        var codes = analysis.Assessments.Select(a => a.Code).ToList();
        Assert.Contains(RdapCodes.ContactValid, codes);
        Assert.Contains(RdapCodes.ExpiryFuture, codes);
    }
}
