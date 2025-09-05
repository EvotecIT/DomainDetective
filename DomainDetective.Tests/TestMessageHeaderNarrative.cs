using System.IO;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestMessageHeaderNarrative
{
    [Fact]
    public void BuildsNarrativeAndPositives()
    {
        var raw = File.ReadAllText("Data/sample-headers.txt");
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        var sections = MessageHeaderNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains(sections.Highlights, h => h.Contains("sender@example.com"));
        Assert.Contains(sections.Details, d => d.Contains("DKIM result: pass"));
        Assert.Contains(sections.Positives, p => p.Contains("DKIM authentication passed"));
        Assert.Contains(sections.Highlights, h => h.Contains("Total transit time"));
    }
}
