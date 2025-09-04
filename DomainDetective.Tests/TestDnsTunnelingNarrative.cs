using System;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsTunnelingNarrative
{
    [Fact]
    public void NarrativeShowsNoIndicators()
    {
        var analysis = new DnsTunnelingAnalysis();
        analysis.Analyze("example.com", Array.Empty<string>());
        var narrative = DnsTunnelingNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains("No tunneling indicators detected.", narrative.Highlights);
    }
}
