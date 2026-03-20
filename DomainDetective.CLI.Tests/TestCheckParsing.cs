using System.Linq;

namespace DomainDetective.CLI.Tests;

public class TestCheckParsing
{
    [Fact]
    public void ParseDomainChecks_SplitsSupportedInvalidAndUnsupportedValues()
    {
        var selected = CommandUtilities.ParseDomainChecks(
            new[] { "whois,arc,bogus,spfflattened" },
            out var invalidChecks,
            out var unsupportedChecks);

        Assert.Equal(new[] { HealthCheckType.WHOIS, HealthCheckType.SPFFLATTENED }, selected);
        Assert.Equal(new[] { "bogus" }, invalidChecks);
        Assert.Equal(new[] { HealthCheckType.ARC }, unsupportedChecks.ToArray());
    }
}
