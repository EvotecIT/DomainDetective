using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestRobotsParser
{
    [Fact]
    public void Parse_GlobalDisallows_Respected()
    {
        string robots = @"User-agent: *
Disallow: /admin
Disallow: /private

User-agent: Googlebot
Disallow: /no-google
";
        var dis = DomainDetective.WebStaticScanAnalysis.ParseRobotsDisallows(robots);
        Assert.Contains("/admin", dis);
        Assert.Contains("/private", dis);
        Assert.DoesNotContain("/no-google", dis);
    }
}

