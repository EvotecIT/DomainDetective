using System;
using System.Reflection;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestIdnValidation
{
    [Theory]
    [InlineData("fe80::1%12", "[fe80::1%12]")]
    [InlineData("[fe80::1%12]", "[fe80::1%12]")]
    [InlineData("[fe80::1%12]:8443", "[fe80::1%12]:8443")]
    [InlineData("[fe80::1%12]:80", "[fe80::1%12]")]
    public void ValidateHostNamePreservesScopedIpv6(string input, string expected) {
        var method = typeof(DomainHealthCheck)
            .GetMethod("ValidateHostName", BindingFlags.NonPublic | BindingFlags.Static)!;
        Assert.Equal(expected, (string)method.Invoke(null, new object[] { input })!);
    }

    [Fact]
    public void ValidateHostNameConvertsUnicode()
    {
        var method = typeof(DomainHealthCheck)
            .GetMethod("ValidateHostName", BindingFlags.NonPublic | BindingFlags.Static)!;
        var result = (string)method.Invoke(null, new object[] { "bücher.de" })!;
        Assert.Equal("xn--bcher-kva.de", result);
    }

    [Fact]
    public void ValidateHostNamePreservesPort()
    {
        var method = typeof(DomainHealthCheck)
            .GetMethod("ValidateHostName", BindingFlags.NonPublic | BindingFlags.Static)!;
        var port = PortHelper.GetFreePort();
        var result = (string)method.Invoke(null, new object[] { $"bücher.de:{port}" })!;
        Assert.Equal($"xn--bcher-kva.de:{port}", result);
        PortHelper.ReleasePort(port);
    }

    [Fact]
    public void ValidateHostNameRejectsNumericTld()
    {
        var method = typeof(DomainHealthCheck)
            .GetMethod("ValidateHostName", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ex = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, new object[] { "example.123" }));
        var inner = Assert.IsType<ArgumentException>(ex.InnerException);
        Assert.Contains("example.123", inner.Message);
    }

    [Fact]
    public void ValidateHostNameRejectsPath()
    {
        var method = typeof(DomainHealthCheck)
            .GetMethod("ValidateHostName", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ex = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, new object[] { "example.com/path" }));
        var inner = Assert.IsType<ArgumentException>(ex.InnerException);
        Assert.Contains("example.com/path", inner.Message);
    }

    [Fact]
    public void ValidateHostNameRejectsBadPort()
    {
        var method = typeof(DomainHealthCheck)
            .GetMethod("ValidateHostName", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ex = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, new object[] { "example.com:65536" }));
        var inner = Assert.IsType<ArgumentException>(ex.InnerException);
        Assert.Contains("65536", inner.Message);
    }

    [Fact]
    public void IsValidTldRequiresLetter()
    {
        Assert.False(DomainDetective.Helpers.DomainHelper.IsValidTld("123"));
        Assert.True(DomainDetective.Helpers.DomainHelper.IsValidTld("com"));
    }
}
