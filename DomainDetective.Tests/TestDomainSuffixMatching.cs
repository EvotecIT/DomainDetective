using DomainDetective.Helpers;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestDomainSuffixMatching {
    [Theory]
    [InlineData("vendor.com", "vendor.com", true)]
    [InlineData("reports.vendor.com", "vendor.com", true)]
    [InlineData("evilvendor.com", "vendor.com", false)]
    [InlineData("reports.vendor.com.", "vendor.com", true)]
    [InlineData("reports.vendor.com", ".vendor.com", true)]
    [InlineData("VENDOR.COM", "vendor.com", true)]
    [InlineData(null, "vendor.com", false)]
    [InlineData("reports.vendor.com", null, false)]
    [InlineData("", "vendor.com", false)]
    [InlineData("reports.vendor.com", "", false)]
    public void IsDomainOrSubdomainOf_EnforcesDotBoundary(string? host, string? suffix, bool expected) {
        var actual = DomainHelper.IsDomainOrSubdomainOf(host, suffix);
        Assert.Equal(expected, actual);
    }
}

