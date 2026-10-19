using DnsClientX;
using System.Net;

namespace DomainDetective.Tests;

public class TestAssessmentTtlIntegration {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnAliasTtlIsNotPresentedAsTheAuthoritativeDkimTxtLifetime(bool includeDestinationTxt) {
        const string owner = "selector._domainkey.example.test";
        var analysis = new DnsTtlAnalysis((_, name, type, _, _, _) => Task.FromResult<DnsResponse?>(new DnsResponse {
            IsAuthoritativeAnswer = true, Status = DnsResponseCode.NoError,
            Answers = name == owner && type == DnsRecordType.TXT
                ? new[] { new DnsAnswer { Name = owner, Type = DnsRecordType.CNAME, DataRaw = "key.provider.test", TTL = 300 } }
                    .Concat(includeDestinationTxt ? new[] { new DnsAnswer { Name = "key.provider.test", Type = DnsRecordType.TXT, DataRaw = "v=DKIM1; p=synthetic", TTL = 1800 } } : Array.Empty<DnsAnswer>()).ToArray()
                : Array.Empty<DnsAnswer>()
        })) { DkimSelectors = new List<string> { "selector" } };
        analysis.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError, Answers = type == DnsRecordType.NS
            ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "ns.example.test", TTL = 3600 } }
            : type == DnsRecordType.A && name == "ns.example.test"
                ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "192.0.2.53", TTL = 3600 } }
                : type == DnsRecordType.TXT && name == owner
                    ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "v=DKIM1; p=synthetic", TTL = 3600 } }
                    : Array.Empty<DnsAnswer>() });
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Equal(new[] { 3600 }, analysis.DkimTxtTtls[owner]);
        Assert.False(analysis.TtlsFromAuthoritativeServers);
        Assert.DoesNotContain(analysis.Assessments, value => value.Code == TtlCodes.TooShort && value.Message.Contains("DKIM"));
    }

    [Fact]
    public async Task OneAuthoritativeSetDoesNotValidateAnotherSetsCacheCountdown() {
        var analysis = new DnsTtlAnalysis {
            QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1", TTL = 12 } }
                : type == DnsRecordType.NS ? new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test", TTL = 12 } } : Array.Empty<DnsAnswer>()),
            AuthoritativeTtlOverride = (_, type) => Task.FromResult(type == DnsRecordType.NS ? (int?)60 : null)
        };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.False(analysis.TtlsFromAuthoritativeServers);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == TtlCodes.TooShort && assessment.Message.StartsWith("NS TTL 60", StringComparison.Ordinal));
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == TtlCodes.TooShort && assessment.Message.StartsWith("A TTL", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthoritativeValueBudgetRetainsKnownSiblingAndDrainsCancellation(bool cancelCaller) {
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        var analysis = new DnsTtlAnalysis(async (_, owner, type, _, token, _) => {
            if (type == DnsRecordType.A) {
                started.TrySetResult(true);
                return new DnsResponse { IsAuthoritativeAnswer = true, Status = DnsResponseCode.NoError,
                    Answers = new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "192.0.2.1", TTL = 60 } } };
            }
            Interlocked.Increment(ref active);
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { Interlocked.Decrement(ref active); }
            return null;
        }) { UniformityQueryTimeoutMs = cancelCaller ? 5000 : 500 };
        analysis.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => Task.FromResult(new DnsResponse {
            Status = DnsResponseCode.NoError,
            Answers = type == DnsRecordType.A ? new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = owner == "ns.example.test" ? "192.0.2.53" : "192.0.2.1", TTL = 12 } }
                : type == DnsRecordType.NS ? new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "ns.example.test", TTL = 12 } } : Array.Empty<DnsAnswer>()
        });
        var run = analysis.Analyze("example.test", new InternalLogger(), caller.Token);
        await started.Task.WaitWithCancellation(guard.Token);
        if (cancelCaller) {
            caller.Cancel();
            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
            Assert.Equal(caller.Token, exception.CancellationToken);
        } else {
            await run.WaitWithCancellation(guard.Token);
            Assert.Equal(new[] { 60 }, analysis.ATtls);
            Assert.False(analysis.TtlsFromAuthoritativeServers);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == TtlCodes.TooShort && assessment.Message.StartsWith("A TTL 60", StringComparison.Ordinal));
        }
        Assert.Equal(0, Volatile.Read(ref active));
    }
}
