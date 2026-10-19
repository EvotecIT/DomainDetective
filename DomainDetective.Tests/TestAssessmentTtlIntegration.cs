using DnsClientX;
using System.Net;

namespace DomainDetective.Tests;

public class TestAssessmentTtlIntegration {
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
