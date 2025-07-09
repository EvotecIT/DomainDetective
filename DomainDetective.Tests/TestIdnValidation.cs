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
        var result = (string)method.Invoke(null, new object[] { "bücher.de:25" })!;
        Assert.Equal("xn--bcher-kva.de:25", result);
    }
}
