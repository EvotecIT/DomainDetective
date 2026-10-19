using System.Collections.Concurrent;
using System.Net;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestDaneExecutionDependencies {
    [Fact]
    public async Task ImplicitDaneCanFinishAfterTheSmtpNetworkProbeWithoutAMissingCoverageWarning() {
        var logger = new InternalLogger();
        var warnings = new ConcurrentQueue<string>();
        logger.OnWarningMessage += (_, item) => warnings.Enqueue(item.Message);
        using var health = new DomainHealthCheck(internalLogger: logger);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var smtpEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.MX
            ? new[] { new DnsAnswer { Type = type, DataRaw = "10 mail.fixture.example" } } : Array.Empty<DnsAnswer>());
        health.DaneDnsOverride = async (name, type) => {
            if (type != DnsRecordType.TLSA) { return Array.Empty<DnsAnswer>(); }
            await smtpEntered.Task.WaitWithCancellation(guard.Token);
            // Keep the wire result pending after SMTP's network boundary returns, so
            // alignment must await its owned evidence rather than an empty analysis.
            await Task.Delay(100, guard.Token);
            return new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "3 1 1 " + new string('0', 64) } };
        };
        health.DaneCertificateEvidenceOverride = (_, _, _) => Task.FromResult<DaneCertificateEvidence?>(new DaneCertificateEvidence { DnssecValidated = true });
        health.OutboundAddressResolver = (_, _) => {
            smtpEntered.TrySetResult(true);
            return Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        };
        health.HttpClientFactory = new StubHttpClientFactory(_ => new System.Net.Http.HttpResponseMessage(HttpStatusCode.NotFound) {
            Content = new System.Net.Http.StringContent("{}")
        });
        await health.Verify("fixture.example", new[] { HealthCheckType.MAILCLASSIFICATION }, cancellationToken: guard.Token,
            executionOptions: new HealthCheckExecutionOptions { MaxParallelism = 8 });
        Assert.Contains(health.DaneAnalysis.AnalysisResults, result => result.ServiceType == ServiceType.SMTP);
        Assert.DoesNotContain(warnings, message => message.Contains("No TLSA coverage"));
    }

    [Theory]
    [InlineData(HealthCheckType.MTASTS, false, 1)]
    [InlineData(HealthCheckType.MTASTS, true, 1)]
    [InlineData(HealthCheckType.SMTPTLS, false, 1)]
    [InlineData(HealthCheckType.MAILCLASSIFICATION, false, 1)]
    [InlineData(HealthCheckType.MAILCLASSIFICATION, true, 2)]
    public async Task SmtpAlignmentUsesTheSelectedOrImplicitDaneOwner(HealthCheckType consumer, bool parallel, int limit) {
        var logger = new InternalLogger();
        var warnings = new ConcurrentQueue<string>();
        logger.OnWarningMessage += (_, item) => warnings.Enqueue(item.Message);
        using var health = new DomainHealthCheck(internalLogger: logger);
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.MX
            ? new[] { new DnsAnswer { Type = type, DataRaw = "10 mail.fixture.example" } }
            : Array.Empty<DnsAnswer>());
        health.DaneDnsOverride = (name, type) => Task.FromResult(type == DnsRecordType.TLSA
            ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "3 1 1 " + new string('0', 64) } }
            : Array.Empty<DnsAnswer>());
        health.DaneCertificateEvidenceOverride = (_, _, _) => Task.FromResult<DaneCertificateEvidence?>(new DaneCertificateEvidence { DnssecValidated = true });
        health.OutboundAddressResolver = (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        health.HttpClientFactory = new StubHttpClientFactory(_ => new System.Net.Http.HttpResponseMessage(HttpStatusCode.NotFound) {
            Content = new System.Net.Http.StringContent("{}")
        });
        var selected = consumer == HealthCheckType.MAILCLASSIFICATION ? new[] { consumer }
            : new[] { consumer, HealthCheckType.DANE };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await health.Verify("fixture.example", selected, cancellationToken: guard.Token,
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = parallel, MaxParallelism = limit });
        Assert.True(health.VerificationCompleted);
        Assert.Equal("fixture.example", health.SmtpTlsAnalysis.Subject);
        Assert.Contains(health.DaneAnalysis.AnalysisResults, result => result.ServiceType == ServiceType.SMTP);
        Assert.DoesNotContain(warnings, message => message.Contains("No TLSA coverage"));
    }
}
