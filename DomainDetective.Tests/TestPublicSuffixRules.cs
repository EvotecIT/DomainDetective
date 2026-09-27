using System.IO;
using System.Text;

namespace DomainDetective.Tests;

public class TestPublicSuffixRules {
    private static PublicSuffixList Load(string rules) {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(rules));
        return PublicSuffixList.Load(stream);
    }

    [Theory]
    [InlineData("a.b.ck", "a.b.ck")]
    [InlineData("c.a.b.ck", "a.b.ck")]
    [InlineData("www.ck", "www.ck")]
    [InlineData("x.www.ck", "www.ck")]
    [InlineData("WWW.CK.", "www.ck")]
    public void WildcardsAndExceptionsSelectRegistrableDomain(string domain, string expected) {
        Assert.Equal(expected, Load("*.ck\n!www.ck\n").GetRegistrableDomain(domain));
    }

    [Theory]
    [InlineData("ck", true)]
    [InlineData("b.ck", true)]
    [InlineData("a.b.ck", false)]
    [InlineData("www.ck", false)]
    [InlineData("x.www.ck", false)]
    public void WildcardMatchesExactlyOneLabel(string domain, bool expected) {
        Assert.Equal(expected, Load("*.ck\n!www.ck\n").IsPublicSuffix(domain));
    }

    [Fact]
    public void UnicodeRulesAndAsciiNamesUseSameCanonicalForm() {
        var list = Load("公司.cn\n");
        Assert.Equal("example.xn--55qx5d.cn", list.GetRegistrableDomain("a.example.公司.cn"));
        Assert.True(list.IsPublicSuffix("xn--55qx5d.cn"));
    }

    [Fact]
    public void LongestRuleAndUnknownSuffixAreSupported() {
        var list = Load("com\nco.uk\nblogspot.com\n");
        Assert.Equal("example.co.uk", list.GetRegistrableDomain("a.example.co.uk"));
        Assert.Equal("tenant.blogspot.com", list.GetRegistrableDomain("a.tenant.blogspot.com"));
        Assert.Equal("example.unknown", list.GetRegistrableDomain("a.example.unknown"));
    }
}
