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
        var rules = DomainDetective.WebStaticScanAnalysis.ParseRobotsRules(robots);
        Assert.False(rules.IsAllowed("/admin/page"));
        Assert.False(rules.IsAllowed("/private/file"));
        Assert.True(rules.IsAllowed("/no-google"));
    }
}

public class TestRobotsAllowPrecedence
{
    [Fact]
    public void Allow_Longest_Match_Wins()
    {
        string robots = @"User-agent: *
Disallow: /pub
Allow: /public
";
        var rules = DomainDetective.WebStaticScanAnalysis.ParseRobotsRules(robots);
        Assert.True(rules.IsAllowed("/public/docs"));
        Assert.False(rules.IsAllowed("/publish"));
    }

    [Fact]
    public void Wildcard_And_EndAnchor_Applied()
    {
        string robots = @"User-agent: *
Disallow: /private/*
Allow: /private/public$
";
        var rules = DomainDetective.WebStaticScanAnalysis.ParseRobotsRules(robots);
        Assert.True(rules.IsAllowed("/private/public"));
        Assert.False(rules.IsAllowed("/private/secret"));
    }
}
