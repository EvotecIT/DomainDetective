using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestEdnsNarrative
{
    [Fact]
    public void BuildSummarizesSupportAndVersion()
    {
        var analysis = new EdnsSupportAnalysis { Subject = "example.com" };
        analysis.ServerSupport["ns1 (192.0.2.1)"] = new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1232, DoBit = true, Version = 0 };
        var sections = EdnsNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("1/1") && h.Contains("support"));
        Assert.Contains(sections.Highlights, h => h.Contains("version 0"));
        Assert.Contains(sections.Details, d => d.Contains("ns1") && d.Contains("1232"));
    }
}

