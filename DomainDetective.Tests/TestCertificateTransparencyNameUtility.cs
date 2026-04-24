using Xunit;

namespace DomainDetective.Tests;

public sealed class TestCertificateTransparencyNameUtility
{
    [Theory]
    [InlineData("WWW.Example.COM.", "www.example.com")]
    [InlineData("*.Example.COM.", "*.example.com")]
    [InlineData(" ", "")]
    public void Normalize_LowercasesAndTrimsRootDot(string name, string expected)
    {
        Assert.Equal(expected, CertificateTransparencyNameUtility.Normalize(name));
    }

    [Theory]
    [InlineData("*.example.com", "*.example.com", null)]
    [InlineData("www.example.com.", "www.example.com", "*.example.com")]
    [InlineData("example.com", "example.com", null)]
    public void SearchNameHelpers_PreserveLiteralWildcardsOnlyForExactPredicate(string name, string expectedExactName, string? expectedImplicitWildcard)
    {
        Assert.Equal(expectedExactName, CertificateTransparencyNameUtility.BuildExactSearchName(name));
        Assert.Equal(expectedImplicitWildcard, CertificateTransparencyNameUtility.BuildImplicitWildcardCandidateName(name));
    }

    [Theory]
    [InlineData("www.example.com", "*.example.com")]
    [InlineData("login.eu.example.com", "*.eu.example.com")]
    [InlineData("*.www.example.com", "*.example.com")]
    [InlineData("example.com", null)]
    [InlineData("localhost", null)]
    public void BuildImmediateWildcardName_ReturnsOnlyCoveringWildcard(string name, string? expected)
    {
        Assert.Equal(expected, CertificateTransparencyNameUtility.BuildImmediateWildcardName(name));
    }

    [Theory]
    [InlineData("api.example.com", "com.example.api.%")]
    [InlineData("foo_bar.example.com", "com.example.foo\\_bar.%")]
    [InlineData("sales%25.example.com", "com.example.sales\\%25.%")]
    [InlineData("weird[host].example.com", "com.example.weird\\[host].%")]
    public void BuildReversedPrefixMatch_EscapesSqlLikeWildcards(string name, string expected)
    {
        Assert.Equal(expected, CertificateTransparencyNameUtility.BuildReversedPrefixMatch(name));
    }

    [Theory]
    [InlineData("www.example.com", "www.example.com", true)]
    [InlineData("www.example.com", "*.example.com", true)]
    [InlineData("api.www.example.com", "*.example.com", false)]
    [InlineData("example.com", "*.example.com", false)]
    [InlineData("www.example.com", "*.www.example.com", false)]
    public void CertificateNameMatchesHost_UsesSingleLabelWildcardCoverage(string hostName, string certificateName, bool expected)
    {
        Assert.Equal(expected, CertificateTransparencyNameUtility.CertificateNameMatchesHost(hostName, certificateName));
    }
}
