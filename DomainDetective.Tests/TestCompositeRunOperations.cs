using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestCompositeRunOperations {
    [Fact]
    public async Task MailCompositeSharesPrerequisitesRetainsSelectorsAndServicesAndRefreshesNextRun() {
        using var health = new DomainHealthCheck();
        var queries = new ConcurrentDictionary<(string, DnsRecordType), int>();
        var http = new ConcurrentDictionary<string, int>();
        health.ExecutionOptions.MaxParallelism = 1;
        health.ExecutionOptions.IncludeMissingDkimSelectors = true;
        health.DnsConfiguration.EnableResponseCache = false;
        health.DnsConfiguration.QueryDnsOverride = (name, type) => {
            queries.AddOrUpdate((name, type), 1, (_, count) => count + 1);
            return Task.FromResult(type == DnsRecordType.MX
                ? new[] { new DnsAnswer { Type = type, DataRaw = "10 mail.example.com" } }
                : Array.Empty<DnsAnswer>());
        };
        var tlsa = new ConcurrentDictionary<string, int>();
        health.DaneDnsOverride = (name, _) => {
            tlsa.AddOrUpdate(name, 1, (_, count) => count + 1);
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };
        health.OutboundAddressResolver = (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        health.HttpClientFactory = new StubHttpClientFactory(request => {
            http.AddOrUpdate(request.RequestUri!.AbsoluteUri, 1, (_, count) => count + 1);
            return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{}") };
        });
        var checks = new[] { HealthCheckType.MAILCLASSIFICATION, HealthCheckType.IDENTITYPROVIDER,
            HealthCheckType.DKIM, HealthCheckType.MTASTS, HealthCheckType.TLSRPT, HealthCheckType.BIMI,
            HealthCheckType.APEXADDRESS, HealthCheckType.DANE, HealthCheckType.SPF, HealthCheckType.MX };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        for (int run = 1; run <= 2; run++) {
            await health.Verify("example.com", checks, new[] { "tenant" }, danePorts: new[] { 8443 }, cancellationToken: guard.Token);
            Assert.NotNull(health.MailDomainClassification);
            Assert.Equal(new[] { "tenant" }, health.DKIMAnalysis.AnalysisResults.Keys);
            Assert.All(Definitions.DKIMSelectors.GuessSelectors(), selector =>
                Assert.Equal(run, queries[($"{selector}._domainkey.example.com", DnsRecordType.TXT)]));
            Assert.Equal(run, queries[("tenant._domainkey.example.com", DnsRecordType.TXT)]);
            Assert.Equal(run, tlsa["_8443._tcp.example.com"]);
            Assert.Equal(run, tlsa["_25._tcp.mail.example.com"]);
            Assert.Contains(8443, health.DaneAnalysis.QueriedPorts);
            Assert.Contains(ServiceType.SMTP, health.DaneAnalysis.QueriedServiceTypes);
            Assert.Contains(http.Keys, url => url.IndexOf("openid-configuration", StringComparison.OrdinalIgnoreCase) >= 0);
            Assert.Contains(http.Keys, url => url.IndexOf("GetUserRealm", StringComparison.OrdinalIgnoreCase) >= 0);
            Assert.All(http.Values, count => Assert.Equal(run, count));
        }
    }

    [Fact]
    public async Task ParentDelegationStartsBeforeUnrelatedAsnEnrichmentFinishes() {
        using var health = new DomainHealthCheck();
        var asnEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var parentEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<int?>(TaskCreationOptions.RunContinuationsAsynchronously);
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => { asnEntered.TrySetResult(true); return release.Task; };
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.NS
            ? new[] { new DnsAnswer { Type = type, DataRaw = "ns1.example.net" } }
            : type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>());
        health.NSAnalysis.QueryDnsFullOverride = (name, type) => {
            parentEntered.TrySetResult(true);
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse {
                Status = DnsResponseCode.NoError,
                Authorities = new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "ns1.example.net" } }
            } });
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var scan = health.Verify("example.com", new[] { HealthCheckType.NS, HealthCheckType.DELEGATION }, cancellationToken: guard.Token);
        try {
            await asnEntered.Task.WaitWithCancellation(guard.Token);
            await parentEntered.Task.WaitWithCancellation(guard.Token);
            Assert.False(scan.IsCompleted);
        } finally { release.TrySetResult(64512); await scan; }
        Assert.True(health.NSAnalysis.DelegationMatches);
        Assert.Equal(64512, Assert.Single(health.NSAnalysis.AsnByIp).Value);
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("2001:db8::1", "[2001:db8::1]")]
    [InlineData("[2001:db8::1]", "[2001:db8::1]")]
    public async Task CombinedWebPlanKeepsPlainHttpSeparateAndHonorsHttpsPort(string domain, string authority) {
        using var health = new DomainHealthCheck();
        var requested = new ConcurrentBag<Uri>();
        health.HttpAnalysis.HttpHandlerFactory = () => new WebHandler(requested);
        health.PlainHttpAnalysis.HttpHandlerFactory = () => new WebHandler(requested);
        health.CertificateAnalysis.PreferTlsHandshakeOnlyProbe = true;
        health.CertificateAnalysis.CaptureExtendedMetadata = false;
        health.CertificateAnalysis.OutboundAddressResolver = (_, _) =>
            Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        var options = new HealthCheckExecutionOptions { IncludePlainHttp = true, WebsitePort = 8443 };
        await health.Verify(domain, new[] { HealthCheckType.HTTP, HealthCheckType.WEBSITE, HealthCheckType.CERT }, executionOptions: options);
        Assert.Equal(2, requested.Count);
        Assert.Contains(requested, uri => uri.Scheme == "https" && uri.Port == 8443);
        Assert.Contains(requested, uri => uri.Scheme == "http" && uri.Port == 80);
        Assert.Equal($"https://{authority}:8443", health.HttpAnalysis.Subject);
        Assert.Equal($"http://{authority}", health.PlainHttpAnalysis.Subject);
        Assert.True(health.HttpAnalysis.IsReachable);
        Assert.True(health.PlainHttpAnalysis.IsReachable);
    }

    [Fact]
    public async Task EmptyApexAnswersAreConclusiveWithoutRepeatedFallbackQueries() {
        using var health = new DomainHealthCheck();
        var queries = new ConcurrentDictionary<DnsRecordType, int>();
        health.DnsConfiguration.EnableResponseCache = false;
        health.DnsConfiguration.QueryDnsOverride = (_, type) => {
            queries.AddOrUpdate(type, 1, (_, count) => count + 1);
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };
        await health.VerifyApexAddresses("empty.example.com");
        Assert.False(health.ApexAddressAnalysis.HasAnyAddress);
        // Confirmed empty discovery has no addresses to enrich or rediscover.
        Assert.True(health.ApexAddressAnalysis.AddressLookupComplete);
        Assert.False(health.ApexAddressAnalysis.AddressPresence);
        Assert.Equal(1, queries[DnsRecordType.A]);
        Assert.Equal(1, queries[DnsRecordType.AAAA]);
    }

    private sealed class WebHandler(ConcurrentBag<Uri> requests) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            requests.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                RequestMessage = request, Content = new StringContent("<html></html>")
            });
        }
    }

}
