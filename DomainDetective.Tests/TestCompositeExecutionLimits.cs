using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestCompositeExecutionLimits {
    [Theory]
    [InlineData(HealthCheckType.MAILCLASSIFICATION, 1)]
    [InlineData(HealthCheckType.MAILCLASSIFICATION, 2)]
    [InlineData(HealthCheckType.MICROSOFT365, 1)]
    [InlineData(HealthCheckType.MICROSOFT365, 2)]
    public async Task MailAndMicrosoftCompositesShareBoundedLeafOwners(HealthCheckType composite, int limit) {
        using var health = new DomainHealthCheck();
        using var admission = new SemaphoreSlim(limit, limit);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        int active = 0, maximum = 0;
        var calls = new ConcurrentDictionary<HealthCheckType, int>();
        var actions = Enum.GetValues(typeof(HealthCheckType)).Cast<HealthCheckType>().ToDictionary(type => type, type => (Func<Task>)(async () => {
            calls.AddOrUpdate(type, 1, (_, count) => count + 1);
            int current = Interlocked.Increment(ref active);
            int observed;
            do { observed = Volatile.Read(ref maximum); }
            while (current > observed && Interlocked.CompareExchange(ref maximum, current, observed) != observed);
            try { await Task.Delay(20, guard.Token); }
            finally { Interlocked.Decrement(ref active); }
        }));
        actions[HealthCheckType.MAILCLASSIFICATION] = () => health.CollectMailClassificationSignalsAsync("fixture.example", guard.Token);
        var microsoft = typeof(DomainHealthCheck).GetMethod("CollectMicrosoft365SignalsAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        actions[HealthCheckType.MICROSOFT365] = () => (Task)microsoft.Invoke(health, new object[] { "fixture.example", guard.Token })!;
        var selected = new[] { composite, HealthCheckType.IDENTITYPROVIDER, HealthCheckType.CAA, HealthCheckType.DMARC };
        typeof(DomainHealthCheck).GetMethod("ConfigureRunOperations", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(health, new object[] { actions, "fixture.example", selected, admission, limit == 1, guard.Token });
        await Task.WhenAll(selected.Select(type => actions[type]())).WaitWithCancellation(guard.Token);
        Assert.InRange(maximum, 1, limit);
        Assert.Equal(0, active);
        Assert.All(calls.Values, count => Assert.Equal(1, count));
        var required = composite == HealthCheckType.MAILCLASSIFICATION
            ? new[] { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.MTASTS,
                HealthCheckType.TLSRPT, HealthCheckType.BIMI, HealthCheckType.IDENTITYPROVIDER, HealthCheckType.DANE, HealthCheckType.APEXADDRESS }
            : new[] { HealthCheckType.IDENTITYPROVIDER, HealthCheckType.DNSINVENTORY, HealthCheckType.SUBDOMAINS,
                HealthCheckType.AUTODISCOVER, HealthCheckType.DKIM };
        foreach (var type in required.Concat(selected.Where(type => type != composite))) { Assert.True(calls.ContainsKey(type), type.ToString()); }
    }

    [Theory]
    [InlineData(false, 8, 1)]
    [InlineData(true, 1, 1)]
    [InlineData(true, 2, 2)]
    public async Task CompositeWebsiteAndPlainHttpHonorTheSharedCheckLimit(bool parallel, int configuredLimit, int expectedLimit) {
        using var health = new DomainHealthCheck();
        int active = 0, maximum = 0, httpCalls = 0, certificates = 0;
        async Task Observe(CancellationToken token) {
            var current = Interlocked.Increment(ref active);
            int observed;
            do { observed = Volatile.Read(ref maximum); }
            while (current > observed && Interlocked.CompareExchange(ref maximum, current, observed) != observed);
            try { await Task.Delay(60, token); }
            finally { Interlocked.Decrement(ref active); }
        }
        var handler = new ObservationHandler(async token => { Interlocked.Increment(ref httpCalls); await Observe(token); });
        health.HttpAnalysis.HttpHandlerFactory = () => handler;
        health.PlainHttpAnalysis.HttpHandlerFactory = () => handler;
        health.CertificateAnalysis.PreferTlsHandshakeOnlyProbe = true;
        health.CertificateAnalysis.CaptureExtendedMetadata = false;
        health.CertificateAnalysis.CaptureCtMetadata = false;
        health.CertificateAnalysis.OutboundAddressResolver = async (_, token) => {
            Interlocked.Increment(ref certificates);
            await Observe(token);
            return Array.Empty<IPAddress>();
        };
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, type, token) => {
            await Observe(token);
            return new DnsResponse { Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.CAA
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "0 issue \"ca.example\"" } }
                    : Array.Empty<DnsAnswer>() };
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await health.Verify("fixture.example", new[] { HealthCheckType.WEBSITE, HealthCheckType.HTTP, HealthCheckType.CERT, HealthCheckType.CAA },
            cancellationToken: guard.Token, executionOptions: new HealthCheckExecutionOptions {
                EnableParallelism = parallel, MaxParallelism = configuredLimit, IncludePlainHttp = true
            });
        Assert.InRange(maximum, 1, expectedLimit);
        Assert.Equal(2, httpCalls);
        Assert.Equal(1, certificates);
        Assert.Equal(0, active);
    }

    private sealed class ObservationHandler(Func<CancellationToken, Task> observe) : HttpMessageHandler {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            await observe(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html></html>") };
        }
    }
}
