using DnsClientX;
using RichardSzalay.MockHttp;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestRpkiValidationContract {
    [Theory]
    [InlineData("valid", RpkiValidationState.Valid, true)]
    [InlineData("invalid_asn", RpkiValidationState.InvalidOriginAsn, false)]
    [InlineData("invalid_length", RpkiValidationState.InvalidPrefixLength, false)]
    [InlineData("unknown", RpkiValidationState.NotFound, false)]
    [InlineData("new_status", RpkiValidationState.QueryFailed, false)]
    public async Task OnlyAuthorizedRoutesAreValid(string status, RpkiValidationState expected, bool valid) {
        using var handler = new MockHttpMessageHandler();
        handler.Expect("https://stat.ripe.net/data/prefix-overview/data.json?resource=192.0.2.1")
            .Respond("application/json", "{\"data\":{\"resource\":\"192.0.2.0/24\",\"asns\":[{\"asn\":64512}]}}");
        handler.Expect("https://stat.ripe.net/data/rpki-validation/data.json?prefix=192.0.2.0%2F24&resource=AS64512")
            .Respond("application/json", "{\"data\":{\"status\":\"" + status + "\"}}");
        using var client = new HttpClient(handler);
        var analysis = new RPKIAnalysis {
            HttpClient = client,
            QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>())
        };
        await analysis.Analyze("example.com", new InternalLogger());
        var result = Assert.Single(analysis.Results);
        Assert.Equal(expected, result.ValidationState);
        Assert.Equal(valid, result.Valid);
        Assert.Equal(valid, analysis.AllValid);
        handler.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task NoAddressesDoesNotEstablishValidation() {
        var analysis = new RPKIAnalysis { QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()) };
        await analysis.Analyze("example.com");
        Assert.False(analysis.AllValid);
    }

    [Fact]
    public async Task CallerCancellationPropagates() {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new RPKIAnalysis().Analyze("example.com", ct: cancellation.Token));
    }
}
