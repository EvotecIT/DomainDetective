using System;
using System.Reflection;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestIdnValidation
{
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
        Assert.IsType<ArgumentException>(ex.InnerException);
    }

    [Fact]
    public void IsValidTldRequiresLetter()
    {
        Assert.False(DomainDetective.Helpers.DomainHelper.IsValidTld("123"));
        Assert.True(DomainDetective.Helpers.DomainHelper.IsValidTld("com"));
    }
}
