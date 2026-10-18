using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestNetworkObservationSharing {
    [Fact]
    public async Task SharedIpObservationAllowsIndependentWaiterDeadlines() {
        using var observations = new Helpers.ScanObservations();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        int active = 0;
        using var client = new HttpClient(new AsyncReply(async (_, token) => {
            Interlocked.Increment(ref calls);
            Interlocked.Increment(ref active);
            entered.TrySetResult(true);
            try { await release.Task.WaitWithCancellation(token); }
            finally { Interlocked.Decrement(ref active); }
            return Json("{\"data\":{\"resource\":\"192.0.2.0/24\",\"asns\":[{\"asn\":64512}]}}");
        }));
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var canceled = CancellationTokenSource.CreateLinkedTokenSource(guard.Token);
        var first = Helpers.IpNetworkMetadata.PrefixAsync(client, "192.0.2.1", canceled.Token);
        await entered.Task.WaitWithCancellation(guard.Token);
        var second = Helpers.IpNetworkMetadata.PrefixAsync(client, "192.0.2.1", guard.Token);
        try {
            canceled.Cancel();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
            Assert.Equal(canceled.Token, error.CancellationToken);
            Assert.Equal(1, calls);
            Assert.Equal(1, active);
            release.TrySetResult(true);
            Assert.Equal(("192.0.2.0/24", 64512), await second);
            Assert.Equal(0, active);
            Assert.Equal(("192.0.2.0/24", 64512), await Helpers.IpNetworkMetadata.PrefixAsync(client, "192.0.2.1", guard.Token));
            Assert.Equal(1, calls);
        } finally {
            release.TrySetResult(true);
            guard.Cancel();
            try { await Task.WhenAll(first, second); } catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public async Task RpkiReusesPrefixValidationPreservesEveryAddressAndRefreshesNextAnalysis() {
        var requests = new ConcurrentDictionary<string, int>();
        using var client = new HttpClient(new AsyncReply(async (request, token) => {
            string path = request.RequestUri!.AbsolutePath;
            requests.AddOrUpdate(path, 1, (_, count) => count + 1);
            await Task.Delay(10, token);
            return Json(path.Contains("prefix-overview")
                ? "{\"data\":{\"resource\":\"192.0.2.0/24\",\"asns\":[{\"asn\":64512}]}}"
                : "{\"data\":{\"status\":\"valid\"}}");
        }));
        var analysis = new RPKIAnalysis {
            HttpClient = client,
            QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" }, new DnsAnswer { Type = type, DataRaw = "192.0.2.2" } }
                : Array.Empty<DnsAnswer>())
        };
        for (int run = 1; run <= 2; run++) {
            await analysis.Analyze("example.com");
            Assert.Equal(new[] { "192.0.2.1", "192.0.2.2" }, analysis.Results.Select(row => row.IpAddress).OrderBy(value => value));
            Assert.All(analysis.Results, row => { Assert.True(row.Valid); Assert.Equal(64512, row.Asn); Assert.Equal("192.0.2.0/24", row.Prefix); });
            Assert.Equal(run * 2, requests["/data/prefix-overview/data.json"]);
            Assert.Equal(run, requests["/data/rpki-validation/data.json"]);
        }
    }

    [Fact]
    public async Task SitemapDownloadsIndependentChildrenTogetherButPublishesInIndexOrder() {
        var bothChildren = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int children = 0;
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new AsyncReply(async (request, token) => {
                string path = request.RequestUri!.AbsolutePath;
                if (path == "/index.xml") {
                    return Xml("<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><sitemap><loc>https://crawl.example/a.xml</loc></sitemap><sitemap><loc>https://crawl.example/b.xml</loc></sitemap></sitemapindex>");
                }
                if (Interlocked.Increment(ref children) == 2) { bothChildren.TrySetResult(true); }
                await release.Task.WaitWithCancellation(token);
                return Xml("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://crawl.example/" + path.Trim('/') + "/</loc></url></urlset>");
            })
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var task = analysis.AnalyzeAsync("https://crawl.example/index.xml", options: new SitemapAnalysisOptions {
            MaxSitemapDocuments = 3, MaxUrlProbes = 0, AllowHttpFallback = false
        }, cancellationToken: guard.Token);
        try { await bothChildren.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); await task; }
        Assert.True(analysis.AnalysisComplete);
        Assert.Equal(2, children);
        Assert.Equal(new[] { "/index.xml", "/a.xml", "/b.xml" }, analysis.Documents.Select(document => new Uri(document.Url).AbsolutePath));
        Assert.Equal(2, analysis.Entries.Count);
    }

    [Theory]
    [InlineData("zen.spamhaus.org", 1)]
    [InlineData("custom.example.test", 2)]
    public async Task DnsblUsesProviderResponseContractForIpv6AndKeepsCustomFallback(string zone, int expectedTypes) {
        var types = new ConcurrentBag<DnsRecordType>();
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL(zone);
        analysis.QueryDnsFullOverride = (names, type) => {
            types.Add(type);
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        };
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "2001:db8::1" }, new InternalLogger(), true, default);
        Assert.Equal(expectedTypes, types.Count);
        Assert.Contains(DnsRecordType.A, types);
        Assert.True(analysis.DiscoverySucceeded);
        Assert.All(analysis.AllResults, row => Assert.True(row.QuerySucceeded));
    }

    [Theory]
    [InlineData(true, 1, false, DnsEndpoint.Cloudflare)]
    [InlineData(true, 1, false, DnsEndpoint.CloudflareWireFormat)]
    [InlineData(false, 2, false, DnsEndpoint.Cloudflare)]
    [InlineData(true, 2, true, DnsEndpoint.Cloudflare)]
    public async Task DnsblSharesOnlyConclusiveAccessFailuresAndRetainsUnknownTargets(bool blocked, int expectedCalls, bool multipleServices, DnsEndpoint endpoint) {
        int calls = 0;
        var analysis = new DNSBLAnalysis(new DnsConfiguration(endpoint, DnsSelectionStrategy.First) {
            ResolverMaxConcurrency = 1
        });
        analysis.ClearDNSBL();
        analysis.AddDNSBL("zen.spamhaus.org");
        if (multipleServices) {
            analysis.DnsConfiguration.DnsEndpoints.Add(DnsEndpoint.Cloudflare);
            analysis.DnsConfiguration.DnsEndpoints.Add(DnsEndpoint.Google);
        }
        analysis.QueryDnsFullOverride = (_, type) => {
            int call = Interlocked.Increment(ref calls);
            if (!blocked && call == 1) { throw new TimeoutException("Temporary response loss."); }
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse {
                Status = blocked && call == 1 ? DnsResponseCode.NoError : DnsResponseCode.NXDomain,
                Answers = blocked && call == 1 ? new[] { new DnsAnswer { Type = type, DataRaw = "127.255.255.254" } } : Array.Empty<DnsAnswer>()
            } });
        };
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1", "192.0.2.2" }, new InternalLogger(), true, default);
        Assert.Equal(expectedCalls, calls);
        Assert.Equal(2, analysis.AllResults.Count);
        Assert.All(analysis.AllResults, row => Assert.False(row.IsBlackListed));
        Assert.Equal(blocked && !multipleServices ? 2 : 1, analysis.AllResults.Count(row => !row.QuerySucceeded));
        Assert.Equal(2, analysis.AllResults.Select(row => row.IpAddress).Distinct().Count());
    }

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body) };
    private static HttpResponseMessage Xml(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/xml") };
    private sealed class AsyncReply(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> reply) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => reply(request, cancellationToken);
    }
}
