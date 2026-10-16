using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestNetworkScheduling {
    [Fact]
    public async Task BatchSharesDnsAdmissionAndRestoresCallerOwnedConfigurations() {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var barrier = new AdmissionBarrier(2, guard.Token);
        var healthChecks = new ConcurrentBag<DomainHealthCheck>();
        int completed = 0;
        int dnssecQueries = 0;
        try {
            await DomainHealthCheck.ProcessBatchAsync(
                Enumerable.Range(0, 8).Select(index => $"item{index}.example.com"),
                (run, ct) => {
                    Assert.Null(run.Error);
                    Interlocked.Increment(ref completed);
                    return Task.CompletedTask;
                }, healthCheckTypes: new[] { HealthCheckType.TTL, HealthCheckType.DNSSEC },
                executionOptions: new HealthCheckExecutionOptions { MaxDomainParallelism = 8, DnsParallelism = 2 },
                healthCheckFactory: _ => {
                    var health = new DomainHealthCheck();
                    health.DnsConfiguration.QueryDnsResponseOverride = async (_, type, ct) => {
                        if (type == DnsRecordType.DNSKEY) { Interlocked.Increment(ref dnssecQueries); }
                        await barrier.EnterAsync();
                        return new DnsResponse { Status = DnsResponseCode.NoError };
                    };
                    healthChecks.Add(health);
                    return health;
                }, cancellationToken: guard.Token);
            Assert.Equal(8, completed);
            Assert.True(dnssecQueries >= 8);
            Assert.Equal(2, barrier.Peak);
            Assert.Equal(0, barrier.Active);
            foreach (var health in healthChecks) {
                Assert.Null(health.DnsConfiguration.QueryAdmissionGate);
                await health.DnsConfiguration.QueryDNS("example.com", DnsRecordType.A, cancellationToken: guard.Token);
            }
        } finally {
            foreach (var health in healthChecks) { health.Dispose(); }
        }
    }

    [Fact]
    public async Task TtlQueriesOverlapWithinBoundAndRetainAllRecordEvidence() {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var barrier = new AdmissionBarrier(8, guard.Token);
        var queries = new ConcurrentBag<(string Name, DnsRecordType Type)>();
        var analysis = new DnsTtlAnalysis {
            QueryDnsOverride = async (name, type) => {
                queries.Add((name, type));
                await barrier.EnterAsync();
                return new[] { new DnsAnswer { Name = name, Type = type, TTL = 600, DataRaw = "v=spf1 -all" } };
            }
        };
        await analysis.Analyze("example.com", new InternalLogger(), guard.Token);
        Assert.Equal(10, queries.Count);
        Assert.Equal(8, barrier.Peak);
        Assert.Equal(0, barrier.Active);
        Assert.Contains(("_dmarc.example.com", DnsRecordType.TXT), queries);
        Assert.Equal(new[] { 600 }, analysis.ATtls);
        Assert.Equal(new[] { 600 }, analysis.AaaaTtls);
        Assert.Equal(new[] { 600 }, analysis.MxTtls);
        Assert.Equal(new[] { 600 }, analysis.NsTtls);
        Assert.Equal(600, analysis.SoaTtl);
        Assert.Equal(new[] { 600 }, analysis.SpfTxtTtls);
    }

    [Fact]
    public async Task TyposquattingQueriesAllCandidatesWithinWorkerBound() {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var barrier = new AdmissionBarrier(12, guard.Token);
        int calls = 0;
        var analysis = new TyposquattingAnalysis {
            MaxDnsParallelism = 3,
            QueryDnsOverride = async (_, type) => {
                Interlocked.Increment(ref calls);
                await barrier.EnterAsync();
                return type == DnsRecordType.A
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } }
                    : Array.Empty<DnsAnswer>();
            }
        };
        await analysis.Analyze("example.com", new InternalLogger(), guard.Token);
        Assert.True(analysis.AnalysisComplete);
        Assert.Equal(analysis.Candidates.Count * 4, calls);
        Assert.Equal(12, barrier.Peak);
        Assert.Equal(0, barrier.Active);
        Assert.Equal(analysis.Variants, analysis.ActiveDomains);
        Assert.All(analysis.Candidates, candidate => {
            Assert.True(candidate.Resolves);
            Assert.False(candidate.DnsChecksIncomplete);
        });
    }

    [Fact]
    public async Task TyposquattingDnsFailureCannotClaimRegistrationAvailability() {
        using var configuration = new DnsConfiguration {
            QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
                Status = type == DnsRecordType.A ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError
            })
        };
        var analysis = new TyposquattingAnalysis { DnsConfiguration = configuration };
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.NotEmpty(analysis.Candidates);
        Assert.False(analysis.AnalysisComplete);
        Assert.All(analysis.Candidates, candidate => {
            Assert.True(candidate.DnsChecksIncomplete);
            Assert.NotEmpty(candidate.DnsQueryErrors);
            Assert.Equal(TyposquattingDisposition.Unknown, candidate.Disposition);
        });
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == TyposquattingCodes.VariantNone);
    }
}

internal sealed class AdmissionBarrier(int required, CancellationToken token) {
    private readonly TaskCompletionSource<bool> _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _active;
    private int _peak;
    internal int Active => _active;
    internal int Peak => _peak;
    internal async Task EnterAsync() {
        int active = Interlocked.Increment(ref _active);
        int previous;
        do { previous = _peak; }
        while (active > previous && Interlocked.CompareExchange(ref _peak, active, previous) != previous);
        if (active >= required) { _release.TrySetResult(true); }
        try { await _release.Task.WaitWithCancellation(token); }
        finally { Interlocked.Decrement(ref _active); }
    }
}

[Collection("HttpListener")]
public class TestSitemapScheduling {
    [Fact]
    public async Task UrlProbesOverlapWithinBoundAndPublishInInputOrder() {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var barrier = new AdmissionBarrier(4, guard.Token);
        var urls = Enumerable.Range(0, 20).Select(index => $"https://example.com/page/{index}").ToArray();
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new Handler(async (request, ct) => {
                if (request.RequestUri!.AbsolutePath == "/sitemap.xml") { return Xml(urls); }
                await barrier.EnterAsync();
                return new HttpResponseMessage(request.RequestUri.AbsolutePath == "/page/0" ? HttpStatusCode.NotFound : HttpStatusCode.OK);
            })
        };
        await analysis.AnalyzeAsync("https://example.com/sitemap.xml", options: new SitemapAnalysisOptions {
            AllowHttpFallback = false, CheckCanonical = false, MaxUrlProbeParallelism = 4
        }, cancellationToken: guard.Token);
        Assert.True(analysis.AnalysisComplete);
        Assert.Equal(urls, analysis.UrlProbes.Select(probe => probe.Url));
        Assert.Equal(4, barrier.Peak);
        Assert.Equal(0, barrier.Active);
        Assert.Equal(1, analysis.ClientErrorCount);
        Assert.Equal(19, analysis.UrlProbes.Count(probe => probe.Success));
    }

    [Fact]
    public async Task WholeAnalysisBudgetCancelsAndObservesAdmittedUrlProbes() {
        int active = 0;
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new Handler(async (request, ct) => {
                if (request.RequestUri!.AbsolutePath == "/sitemap.xml") {
                    return Xml(Enumerable.Range(0, 20).Select(index => $"https://example.com/page/{index}"));
                }
                Interlocked.Increment(ref active);
                try { await Task.Delay(Timeout.Infinite, ct); }
                finally { Interlocked.Decrement(ref active); }
                return new HttpResponseMessage(HttpStatusCode.OK);
            })
        };
        await analysis.AnalyzeAsync("https://example.com/sitemap.xml", options: new SitemapAnalysisOptions {
            AllowHttpFallback = false, CheckCanonical = false, MaxUrlProbeParallelism = 4,
            AnalysisTimeout = TimeSpan.FromMilliseconds(100)
        });
        Assert.False(analysis.AnalysisComplete);
        Assert.Equal(0, active);
        Assert.Empty(analysis.UrlProbes);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "SITEMAP.Analysis.Incomplete");
    }

    private static HttpResponseMessage Xml(IEnumerable<string> urls) => new(HttpStatusCode.OK) {
        Content = new StringContent("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" +
            string.Concat(urls.Select(url => $"<url><loc>{url}</loc></url>")) + "</urlset>", System.Text.Encoding.UTF8, "application/xml")
    };

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }
}
