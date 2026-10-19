using DnsClientX;
using System.Net;
using System.Net.Http;

namespace DomainDetective.Tests;

public class TestScanPartialEvidence {
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task SitemapKeepsCompletedSiblingsWhenAnotherDownloadIsCanceled(bool completedFirst, bool callerCancellation) {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        // XML/schema initialization is setup, not the sibling cancellation under test.
        var warmup = new SitemapAnalysis {
            HttpHandlerFactory = () => new DelegateHandler((_, _) => Task.FromResult(Xml(
                "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></urlset>")))
        };
        await warmup.AnalyzeAsync("https://partial.example/warmup.xml", options: new SitemapAnalysisOptions {
            AllowHttpFallback = false, ProbeUrls = false
        }, cancellationToken: guard.Token);
        Assert.True(warmup.AnalysisComplete);

        using var caller = CancellationTokenSource.CreateLinkedTokenSource(guard.Token);
        var stalled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var completed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool drained = false;
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new DelegateHandler(async (request, token) => {
                string name = request.RequestUri!.AbsolutePath;
                if (name == "/sitemap.xml") {
                    string first = completedFirst ? "complete.xml" : "stalled.xml";
                    string second = completedFirst ? "stalled.xml" : "complete.xml";
                    return Xml("<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" +
                        $"<sitemap><loc>https://partial.example/{first}</loc></sitemap>" +
                        $"<sitemap><loc>https://partial.example/{second}</loc></sitemap></sitemapindex>");
                }
                if (name == "/complete.xml") {
                    return Xml("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" +
                        "<url><loc>https://partial.example/retained</loc></url></urlset>", () => completed.TrySetResult(true));
                }
                stalled.TrySetResult(true);
                try { await Task.Delay(Timeout.Infinite, token); }
                finally { drained = true; }
                throw new InvalidOperationException("The canceled download must not finish normally.");
            })
        };
        Task operation = analysis.AnalyzeAsync("https://partial.example/sitemap.xml", options: new SitemapAnalysisOptions {
            AnalysisTimeout = TimeSpan.FromSeconds(callerCancellation ? 20 : 10),
            MaxSitemapDocuments = 3, AllowHttpFallback = false, ProbeUrls = false
        }, cancellationToken: caller.Token);
        try {
            Task siblingsEntered = Task.WhenAll(stalled.Task, completed.Task);
            Assert.Same(siblingsEntered, await Task.WhenAny(siblingsEntered, operation).WaitWithCancellation(guard.Token));
            await siblingsEntered;
            if (callerCancellation) { caller.Cancel(); }
            if (callerCancellation) { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation); }
            else { await operation; }
            Assert.False(analysis.AnalysisComplete);
            Assert.True(drained);
            Assert.Equal(new[] { "https://partial.example/sitemap.xml", "https://partial.example/complete.xml" }, analysis.Documents.Select(document => document.Url));
            Assert.Equal("https://partial.example/retained", Assert.Single(analysis.Entries).Location);
        } finally {
            caller.Cancel();
            try { await operation; } catch (OperationCanceledException) when (caller.IsCancellationRequested) { }
        }
    }

    [Theory]
    [InlineData(HealthCheckType.REVERSEDNS)]
    [InlineData(HealthCheckType.FCRDNS)]
    public async Task ReverseDnsPlanObservesCallerCancellationAfterMxDiscovery(HealthCheckType check) {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var caller = new CancellationTokenSource();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<DnsAnswer[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.MX
            ? new[] { new DnsAnswer { DataRaw = "0 mail.cancel.example" } } : Array.Empty<DnsAnswer>());
        health.ReverseDnsAnalysis.QueryDnsOverride = (_, _) => {
            entered.TrySetResult(true);
            return release.Task;
        };
        Task operation = health.Verify("cancel.example", new[] { check }, cancellationToken: caller.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            caller.Cancel();
            Assert.Same(operation, await Task.WhenAny(operation, Task.Delay(3000, guard.Token)));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
        } finally {
            release.TrySetResult(Array.Empty<DnsAnswer>());
            try { await operation; } catch (OperationCanceledException) when (caller.IsCancellationRequested) { }
        }
    }

    private static HttpResponseMessage Xml(string body, Action? completed = null) => new(HttpStatusCode.OK) {
        Content = completed == null ? new StringContent(body) : new CompletedContent(body, completed)
    };

    private sealed class CompletedContent(string body, Action completed) : StringContent(body) {
        protected override void Dispose(bool disposing) {
            base.Dispose(disposing);
            if (disposing) { completed(); }
        }
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }
}
