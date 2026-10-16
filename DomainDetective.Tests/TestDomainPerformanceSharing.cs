using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestDomainPerformanceSharing {
    [Fact]
    public async Task NsAndDelegationShareChildAnalysisAndRefreshOnNextRun() {
        using var health = new DomainHealthCheck();
        var calls = new ConcurrentDictionary<(string, DnsRecordType), int>();
        var names = new[] { "ns1.example.net", "ns1.example.net", "ns2.example.net" };
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => Task.FromResult<int?>(null);
        health.DnsConfiguration.QueryDnsResponseOverride = async (name, type, ct) => {
            calls.AddOrUpdate((name, type), 1, (_, count) => count + 1);
            await Task.Delay(5, ct);
            return new DnsResponse {
                Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.NS
                    ? names.Select(value => new DnsAnswer { Type = type, DataRaw = value }).ToArray()
                    : type == DnsRecordType.A
                        ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } }
                        : Array.Empty<DnsAnswer>()
            };
        };
        for (int run = 1; run <= 2; run++) {
            await health.Verify("example.com", new[] { HealthCheckType.NS, HealthCheckType.DELEGATION });
            Assert.Equal(names, health.NSAnalysis.NsRecords);
            Assert.True(health.NSAnalysis.HasDuplicates);
            Assert.True(health.NSAnalysis.DelegationMatches);
            Assert.Equal(run, calls[("ns1.example.net", DnsRecordType.A)]);
            Assert.Equal(run * 2, calls[("example.com", DnsRecordType.NS)]); // child plus parent evidence
        }
    }

    [Fact]
    public async Task CompositeWebsiteChecksShareCompatibleWorkButDirectCallsRefresh() {
        using var health = new DomainHealthCheck();
        int requests = 0;
        int certificatePaths = 0;
        health.HttpAnalysis.HttpHandlerFactory = () => new SuccessfulHandler(() => Interlocked.Increment(ref requests));
        health.CertificateAnalysis.OutboundAddressResolver = (_, _) => {
            Interlocked.Increment(ref certificatePaths);
            return Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        };
        await health.Verify("example.com", new[] { HealthCheckType.WEBSITE, HealthCheckType.HTTP, HealthCheckType.CERT });
        Assert.Equal(1, requests);
        Assert.Equal(1, certificatePaths);
        Assert.True(health.HttpAnalysis.IsReachable);
        await health.VerifyWebsiteHttps("example.com");
        Assert.Equal(2, requests);
        await health.Verify("example.com", new[] { HealthCheckType.WEBSITE, HealthCheckType.HTTP, HealthCheckType.CERT });
        Assert.Equal(3, requests);
        Assert.Equal(2, certificatePaths);
    }

    private sealed class SuccessfulHandler(Action onRequest) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            onRequest();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html></html>") });
        }
    }
}
