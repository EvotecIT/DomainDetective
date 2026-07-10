using System.Net;
using DomainDetective.Security;

namespace DomainDetective.Tests;

public class TestPublicNetworkTargetValidator {
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("100.64.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    [InlineData("2001:db8::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("64:ff9b::127.0.0.1")]
    [InlineData("2001::1")]
    [InlineData("2002:0a00:0001::")]
    public void SpecialUseAddressesAreRejected(string value) {
        Assert.False(PublicNetworkTargetValidator.IsPublicAddress(IPAddress.Parse(value)));
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
    public void PublicAddressesAreAllowed(string value) {
        Assert.True(PublicNetworkTargetValidator.IsPublicAddress(IPAddress.Parse(value)));
    }

    [Fact]
    public async Task MixedPublicAndPrivateResolutionIsRejected() {
        var validator = new PublicNetworkTargetValidator((_, _) => Task.FromResult(new[] {
            IPAddress.Parse("1.1.1.1"),
            IPAddress.Parse("10.0.0.1")
        }));

        var result = await validator.ValidateAsync("mixed.example");

        Assert.False(result.IsAllowed);
        Assert.Contains("non-public", result.Error);
    }

    [Fact]
    public async Task ResolutionFailureIsRejected() {
        var validator = new PublicNetworkTargetValidator((_, _) => throw new System.Net.Sockets.SocketException());

        var result = await validator.ValidateAsync("missing.example");

        Assert.False(result.IsAllowed);
        Assert.Contains("could not be resolved", result.Error);
    }
}
