namespace DomainDetective.Tests;

public class TestSnmpAnalysis
{
    [Fact]
    public async Task DetectsSnmpResponse()
    {
        var analysis = new SnmpAnalysis { SnmpTestOverride = (_, _) => Task.FromResult(true) };
        await analysis.AnalyzeServer("host", 161, new InternalLogger());
        Assert.True(analysis.ServerResults["host:161"]);
    }

    [Fact]
    public async Task ResetsResultsBetweenRuns()
    {
        var analysis = new SnmpAnalysis { SnmpTestOverride = (_, _) => Task.FromResult(true) };
        await analysis.AnalyzeServer("a", 161, new InternalLogger());
        await analysis.AnalyzeServer("b", 161, new InternalLogger());
        Assert.False(analysis.ServerResults.ContainsKey("a:161"));
        Assert.True(analysis.ServerResults["b:161"]);
    }
}
