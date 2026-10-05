using DnsClientX;
using RichardSzalay.MockHttp;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestMtaStsPolicyContract {
    [Theory]
    [InlineData("none", "", 3600)]
    [InlineData("enforce", "mx: mail.example.com\n", 0)]
    public async Task WithdrawalAndZeroAgePoliciesAreValid(string mode, string mx, int age) {
        using var handler = new MockHttpMessageHandler();
        handler.When("https://mta-sts.example.com/*")
            .Respond("text/plain", $"version: STSv1\nmode: {mode}\n{mx}max_age: {age}\n");
        using var client = new HttpClient(handler);
        var analysis = Create(client);
        await analysis.AnalyzePolicy("example.com", new InternalLogger());
        Assert.True(analysis.PolicyValid);
        Assert.Equal(age, analysis.MaxAge);
    }

    [Fact]
    public async Task CachedPolicyUsesCurrentMxObservations() {
        using var handler = new MockHttpMessageHandler();
        handler.Expect("https://mta-sts.example.com/*")
            .Respond("text/plain", "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 3600\n");
        using var client = new HttpClient(handler);
        var analysis = Create(client);
        string host = "mail.example.com";
        analysis.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(new[] {
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 " + host }
        });
        await analysis.AnalyzePolicy("example.com", new InternalLogger());
        Assert.True(analysis.MxAligned);
        host = "new.example.com";
        await analysis.AnalyzePolicy("example.com", new InternalLogger());
        Assert.True(analysis.PolicyValid);
        Assert.False(analysis.MxAligned);
        Assert.Equal("new.example.com", Assert.Single(analysis.MissingMxFromPolicy));
        handler.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task ZeroAgeDoesNotCacheTheFetchedPolicy() {
        using var handler = new MockHttpMessageHandler();
        for (int i = 0; i < 2; i++) {
            handler.Expect("https://mta-sts.example.com/*")
                .Respond("text/plain", "version: STSv1\nmode: none\nmax_age: 0\n");
        }
        using var client = new HttpClient(handler);
        var analysis = Create(client);
        await analysis.AnalyzePolicy("example.com", new InternalLogger());
        await analysis.AnalyzePolicy("example.com", new InternalLogger());
        handler.VerifyNoOutstandingExpectation();
    }

    private static MTASTSAnalysis Create(HttpClient client) => new() {
        HttpClient = client,
        PolicyUrlOverride = "https://mta-sts.example.com/" + Guid.NewGuid().ToString("N"),
        QueryDnsOverride = (_, _) => Task.FromResult(new[] {
            new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = "v=STSv1; id=1;" }
        }),
        DnsConfiguration = new DnsConfiguration { QueryDnsOverride = (_, _) => Task.FromResult(new[] {
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 mail.example.com" }
        }) }
    };
}
