namespace DomainDetective.Tests;

public class TestOpenResolverAnalysis {
    [Fact]
    public async Task DetectsRecursionAllowed() {
        var analysis = new OpenResolverAnalysis { RecursionTestOverride = (_, _) => Task.FromResult(true) };
        var port = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("server", port, new InternalLogger());
        Assert.True(analysis.ServerResults[$"server:{port}"]);
        PortHelper.ReleasePort(port);
    }

    [Fact]
    public async Task DetectsRecursionDisabled() {
        var analysis = new OpenResolverAnalysis { RecursionTestOverride = (_, _) => Task.FromResult(false) };
        var port = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("server", port, new InternalLogger());
        Assert.False(analysis.ServerResults[$"server:{port}"]);
        PortHelper.ReleasePort(port);
    }

    [Fact]
    public async Task ResultsResetBetweenRuns() {
        var analysis = new OpenResolverAnalysis { RecursionTestOverride = (_, _) => Task.FromResult(true) };
        var portA = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("a", portA, new InternalLogger());
        var portB = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("b", portB, new InternalLogger());
        Assert.False(analysis.ServerResults.ContainsKey($"a:{portA}"));
        Assert.True(analysis.ServerResults[$"b:{portB}"]);
        PortHelper.ReleasePort(portA);
        PortHelper.ReleasePort(portB);
    }
}