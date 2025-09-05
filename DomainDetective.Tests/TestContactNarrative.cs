using DomainDetective.Narratives;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestContactNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithFields()
    {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.CheckContactInfo("email=admin@example.com; phone=12345");
        var sections = ContactNarrative.Build(healthCheck.ContactInfoAnalysis, healthCheck.ContactInfoAnalysis.Assessments);
        Assert.Contains(sections.Highlights, h => h.Contains("Contact TXT record found"));
        Assert.Contains(sections.Details, d => d.Contains("email"));
    }
}
