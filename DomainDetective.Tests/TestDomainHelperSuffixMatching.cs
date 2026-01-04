using DomainDetective.Helpers;
using Xunit;

namespace DomainDetective.Tests;

public class TestDomainHelperSuffixMatching {
    [Theory]
    [InlineData("vendor.com", "vendor.com", true)]
    [InlineData("reports.vendor.com", "vendor.com", true)]
    [InlineData("evilvendor.com", "vendor.com", false)]
    [InlineData("reports.vendor.com.", "vendor.com", true)]
    [InlineData("reports.vendor.com", "vendor.com.", true)]
    [InlineData("VENDOR.COM", "vendor.com", true)]
    [InlineData("reports.vendor.com", "VENDOR.COM", true)]
    [InlineData("", "vendor.com", false)]
    [InlineData("reports.vendor.com", "", false)]
    [InlineData(null, "vendor.com", false)]
    [InlineData("reports.vendor.com", null, false)]
    public void IsDomainOrSubdomainOf_BoundarySafe(string? host, string? domain, bool expected) {
        Assert.Equal(expected, DomainHelper.IsDomainOrSubdomainOf(host, domain));
    }
}
