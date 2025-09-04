using System.Linq;
using DomainDetective.Narratives;

namespace DomainDetective.Tests;

public class TestWhoisNarrative
{
    [Fact]
    public void WhoisNarrativeSummarizesFields()
    {
        var sample = "   Domain Name: EXAMPLE.COM\n   Registrar: Example Registrar\n   Registry Expiry Date: 2035-01-01T00:00:00Z\n   Registrar Abuse Contact Email: admin@example.com\n   Name Server: NS1.EXAMPLE.COM\n   Name Server: NS2.EXAMPLE.COM\n   DNSSEC: unsigned\n";
        var whois = new WhoisAnalysis { DomainName = "example.com", WhoisData = sample };
        var tldProp = typeof(WhoisAnalysis).GetProperty("TLD", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        tldProp!.SetValue(whois, "com");
        var parse = typeof(WhoisAnalysis).GetMethod("ParseWhoisData", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        parse!.Invoke(whois, null);
        whois.RegisteredTo = "Example Corp";

        var sections = WhoisNarrative.Build(whois);
        Assert.Contains("Registered to Example Corp", sections.Highlights);
        Assert.Contains("WHOIS privacy protection not enabled", sections.Highlights);
        Assert.Contains($"Expires on {whois.ExpiryDate}", sections.Highlights);
        var codes = whois.Assessments.Select(a => a.Code).ToList();
        Assert.Contains(WhoisCodes.ContactValid, codes);
        Assert.Contains(WhoisCodes.ExpiryFuture, codes);
    }
}
