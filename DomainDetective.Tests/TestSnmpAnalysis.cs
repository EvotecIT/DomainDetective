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
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReuseKeepsOnlyCurrentRunAssessmentsAndAutomaticSubject(bool multiple) {
        var analysis = new SnmpAnalysis { SnmpTestOverride = (host, _) => Task.FromResult(host == "first") };
        await analysis.AnalyzeServer("first", 161, new InternalLogger());
        Assert.Contains(analysis.Assessments, item => item.Code == SnmpCodes.Responds);
        if (multiple) {
            await analysis.AnalyzeServers(new[] { "second" }, new[] { 161 }, new InternalLogger());
        } else {
            await analysis.AnalyzeServer("second", 161, new InternalLogger());
        }
        Assert.Single(analysis.ServerResults);
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == SnmpCodes.Responds);
        Assert.All(analysis.Assessments, item => Assert.Equal("second:161", item.Target));
        Assert.Equal(multiple ? null : "second:161", analysis.Subject);
    }

    [Fact]
    public async Task ReusePreservesCallerSpecifiedSubject() {
        var analysis = new SnmpAnalysis { Subject = "custom display label", SnmpTestOverride = (_, _) => Task.FromResult(false) };
        await analysis.AnalyzeServer("first", 161, new InternalLogger());
        await analysis.AnalyzeServers(new[] { "second" }, new[] { 161 }, new InternalLogger());
        Assert.Equal("custom display label", analysis.Subject);
    }
}
