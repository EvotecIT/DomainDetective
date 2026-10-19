using DnsClientX;
using System.Net;
using System.Net.Http;
using System.Reflection;

namespace DomainDetective.Tests;

[Collection("CtSharedState")]
public class TestCtBottleneckReviewClosure {
    [Fact]
    public async Task SuccessfulHeadersDoNotRemoveClientDeadlineFromBodyRead() {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var client = new HttpClient(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
            Content = new HeldContent(release.Task)
        }))) { Timeout = TimeSpan.FromMilliseconds(100) };
        var aggregator = new CtLogAggregator { MinimumRequestSpacing = TimeSpan.Zero, MaxAttemptsPerRequest = 1 };
        var requestType = typeof(CtLogAggregator).GetNestedType("CtDiscoveryRequest", BindingFlags.NonPublic)!;
        var parserType = typeof(CtLogAggregator).GetNestedType("CtResponseParserKind", BindingFlags.NonPublic)!;
        object request = Activator.CreateInstance(requestType, new object?[] {
            "synthetic", "https://example.test/ct", "synthetic", Enum.ToObject(parserType, 0), null, null
        })!;
        var method = typeof(CtLogAggregator).GetMethod("FetchEntriesWithRetryAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var run = (Task)method.Invoke(aggregator, new[] { client, request, (object)CancellationToken.None })!;
        try {
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
            Assert.NotEqual(guard.Token, error.CancellationToken);
            Assert.True(run.IsCompleted);
        } finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) { } }
    }

    [Fact]
    public async Task SourceCompletionCancellationPreservesOriginalCallerToken() {
        CtLogAggregator.ResetSharedStateForTests();
        using var caller = new CancellationTokenSource();
        var aggregator = new CtLogAggregator {
            MinimumRequestSpacing = TimeSpan.Zero,
            HttpHandlerFactory = () => new Handler((_, _) => {
                caller.Cancel();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]") });
            })
        };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://" + Guid.NewGuid().ToString("N") + ".example.test/{0}");
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => aggregator.QueryWithResultAsync("synthetic", caller.Token));
        Assert.Equal(caller.Token, error.CancellationToken);
        Assert.False(aggregator.LastQueryComplete);
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }

    private sealed class HeldContent(Task release) : HttpContent {
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context) { await release; }
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }
}

public class TestTtlBottleneckReviewClosure {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FixedTtlSourceFailureRetainsSuccessfulSiblingEvidence(bool dnsFailure) {
        var analysis = new DnsTtlAnalysis { QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.A || type == DnsRecordType.NS
            ? new[] { Answer(type, type == DnsRecordType.NS ? "ns.example.test" : "192.0.2.1") } : Array.Empty<DnsAnswer>()) };
        analysis.AuthoritativeTtlOverride = (_, type) => type == DnsRecordType.A ? Task.FromResult<int?>(600)
            : Task.FromException<int?>(dnsFailure ? new DnsClientException("synthetic") : new TimeoutException("synthetic"));
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Equal(600, Assert.Single(analysis.ATtls));
        Assert.Equal(300, Assert.Single(analysis.NsTtls));
        Assert.False(analysis.TtlsFromAuthoritativeServers);
    }

    [Theory]
    [InlineData(20, true)]
    [InlineData(900, false)]
    [InlineData(1500, true)]
    public async Task HealthyServerCompletesEveryRrsetWithinOriginalBudget(int replyDelay, bool alternative) {
        var firstWave = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var alternativeEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int healthyStarted = 0;
        var analysis = new DnsTtlAnalysis(async (server, owner, type, _, token, _) => {
            if (server.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) {
                alternativeEntered.TrySetResult(true);
                await Task.Delay(Timeout.Infinite, token);
            } else {
                if (Interlocked.Increment(ref healthyStarted) == 1) { firstWave.TrySetResult(true); }
                if (alternative) { await alternativeEntered.Task.WaitWithCancellation(token); }
                await Task.Delay(replyDelay, token);
            }
            return new DnsResponse { IsAuthoritativeAnswer = true, Answers = new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "synthetic", TTL = 600 } } };
        }) { UniformityQueryTimeoutMs = 4000 };
        analysis.DnsConfiguration.QueryDnsResponseOverride = async (owner, type, token) => {
            if (owner == "ns.example.test") {
                if (type == DnsRecordType.AAAA && !alternative) { return new DnsResponse(); }
                if (type == DnsRecordType.AAAA) { await firstWave.Task.WaitWithCancellation(token); }
                return new DnsResponse { Answers = new[] { Answer(type, type == DnsRecordType.A ? "192.0.2.1" : "2001:db8::1") } };
            }
            string data = type == DnsRecordType.NS ? "ns.example.test" : type == DnsRecordType.TXT
                ? owner.StartsWith("_dmarc.") ? "v=DMARC1" : owner.StartsWith("_mta-sts.") ? "v=STSv1"
                    : owner.StartsWith("_smtp.") ? "v=TLSRPTv1" : "v=spf1 -all" : "synthetic";
            return new DnsResponse { Answers = type == DnsRecordType.DS ? Array.Empty<DnsAnswer>() : new[] { Answer(type, data) } };
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await analysis.Analyze("example.test", new InternalLogger(), guard.Token);
        Assert.Equal(9, healthyStarted);
        Assert.Equal(600, Assert.Single(analysis.TlsRptTxtTtls));
        Assert.True(analysis.TtlsFromAuthoritativeServers);
    }

    [Fact]
    public async Task CallerCancellationDrainsEveryAdmittedTtlProbe() {
        int active = 0;
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var caller = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var analysis = new DnsTtlAnalysis(async (_, _, _, _, token, _) => {
            Interlocked.Increment(ref active);
            entered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); return null; }
            finally { Interlocked.Decrement(ref active); }
        });
        analysis.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => Task.FromResult(new DnsResponse {
            Answers = owner == "ns.example.test" ? type == DnsRecordType.A ? new[] { Answer(type, "192.0.2.1") } : Array.Empty<DnsAnswer>()
                : type == DnsRecordType.A ? new[] { Answer(type, "192.0.2.44") }
                    : type == DnsRecordType.NS ? new[] { Answer(type, "ns.example.test") } : Array.Empty<DnsAnswer>()
        });
        var run = analysis.Analyze("example.test", new InternalLogger(), caller.Token);
        await entered.Task.WaitWithCancellation(caller.Token);
        caller.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(caller.Token, error.CancellationToken);
        Assert.Equal(0, Volatile.Read(ref active));
        Assert.False(analysis.TtlsFromAuthoritativeServers);
    }

    private static DnsAnswer Answer(DnsRecordType type, string value) => new() { Type = type, DataRaw = value, TTL = 300 };
}
