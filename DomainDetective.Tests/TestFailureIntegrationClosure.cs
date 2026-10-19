using DnsClientX;
using DomainDetective.Reports;
using DomainDetective.Views;
using System.Net;
using System.Net.Http;

namespace DomainDetective.Tests;

public class TestFailureIntegrationClosure {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompletedSupplementalTakeoverIsRetainedBesideSelectedEvidence(bool supplementalOnly) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => Task.FromResult(new DnsResponse {
            Status = DnsResponseCode.NoError,
            Answers = type == DnsRecordType.CNAME ? new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "fixture.azurewebsites.net" } } : Array.Empty<DnsAnswer>()
        });
        await health.Verify("fixture.example.test", supplementalOnly ? Array.Empty<HealthCheckType>() : new[] { HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { IncludeTakeoverCname = true }, useDefaultChecksWhenEmpty: false);
        Assert.True(health.VerificationTakeoverCompleted);
        var items = HealthCheckReportItems.BuildItems(health, "fixture.example.test", null, false, new());
        Assert.Contains(AssessmentEvidenceInfo.Collect(items).SelectMany(item => item.Assessments),
            assessment => assessment.Code == TakeoverCnameCodes.RiskyProvider);
        Assert.Contains(AssessmentEvidenceInfo.Collect(items).SelectMany(item => item.Recommendations),
            recommendation => recommendation.Code == TakeoverCnameCodes.RiskyProvider);
    }

    [Fact]
    public async Task CompletedPlainHttpFindingsAreRetainedOnlyForTheCurrentRun() {
        using var health = new DomainHealthCheck();
        health.PlainHttpAnalysis.HttpHandlerFactory = () => new Handler();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await health.Verify("fixture.example.test", new[] { HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { IncludePlainHttp = true });
        var expected = health.PlainHttpAnalysis.Assessments.ToArray();
        Assert.NotEmpty(expected);
        var items = HealthCheckReportItems.BuildItems(health, "fixture.example.test", null, false, new());
        var findings = AssessmentEvidenceInfo.Collect(items).SelectMany(item => item.Assessments).ToArray();
        Assert.All(expected, assessment => Assert.Contains(assessment, findings));
        await health.Verify("next.example.test", new[] { HealthCheckType.CAA });
        var next = HealthCheckReportItems.BuildItems(health, "next.example.test", null, false, new());
        Assert.All(AssessmentEvidenceInfo.Collect(next).SelectMany(item => item.Assessments), assessment => Assert.DoesNotContain(assessment, expected));
    }

    [Fact]
    public async Task CompletedImplicitWebsiteOwnersRemainConvertibleInFilteredSnapshots() {
        using var health = new DomainHealthCheck();
        health.HttpAnalysis.HttpHandlerFactory = () => new Handler();
        health.CertificateAnalysis.CaptureExtendedMetadata = false;
        health.CertificateAnalysis.PreferTlsHandshakeOnlyProbe = true;
        health.CertificateAnalysis.OutboundAddressResolver = (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        await health.Verify("fixture.example.test", new[] { HealthCheckType.WEBSITE });
        foreach (var check in new[] { HealthCheckType.HTTP, HealthCheckType.CERT }) {
            Assert.Contains(check, health.VerificationCompletedChecks);
            Assert.DoesNotContain(Converters.ConvertChecks(health, new[] { check }), item => item is CheckFailureInfo);
            using var snapshot = health.FilterAnalyses(new[] { check });
            Assert.DoesNotContain(Converters.ConvertChecks(snapshot, new[] { check }), item => item is CheckFailureInfo);
        }
        Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(health, new[] { HealthCheckType.CAA })));
    }

    [Fact]
    public async Task SelectedFailureRetainsOriginalIdentityAfterSupplementalFailureDrains() {
        using var health = new DomainHealthCheck();
        var selected = new TimeoutException("Selected CAA failure.");
        var auxiliary = new InvalidOperationException("Supplemental CNAME failure.");
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => type == DnsRecordType.CAA ? throw selected
            : type == DnsRecordType.CNAME ? throw auxiliary : Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        var actual = await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("fixture.example.test", new[] { HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { IncludeTakeoverCname = true }));
        Assert.Same(selected, actual);
        Assert.Equal(selected.Message, health.VerificationError);
        Assert.False(health.VerificationTakeoverCompleted);
    }

    [Fact]
    public async Task CallerCancellationWinsOverSelectedFailureAfterAuxiliaryDrain() {
        using var health = new DomainHealthCheck();
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var selectedEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, type, token) => {
            if (type == DnsRecordType.CAA) { selectedEntered.TrySetResult(true); throw new TimeoutException("Selected failure."); }
            if (type == DnsRecordType.CNAME) {
                await selectedEntered.Task.WaitWithCancellation(guard.Token);
                caller.Cancel();
                token.ThrowIfCancellationRequested();
            }
            return new DnsResponse { Status = DnsResponseCode.NoError };
        };
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.Verify("fixture.example.test", new[] { HealthCheckType.CAA },
            cancellationToken: caller.Token, executionOptions: new HealthCheckExecutionOptions { IncludeTakeoverCname = true }));
        Assert.Equal(caller.Token, exception.CancellationToken);
    }

    [Fact]
    public async Task FatalAuxiliaryExceptionIsNotHiddenByDeferredSelectedFailure() {
        using var health = new DomainHealthCheck();
        var fatal = new OutOfMemoryException("Synthetic fatal boundary; no allocation pressure.");
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => type == DnsRecordType.CAA ? throw new TimeoutException("Selected failure.")
            : type == DnsRecordType.CNAME ? throw fatal : Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        Assert.Same(fatal, await Assert.ThrowsAsync<OutOfMemoryException>(() => health.Verify("fixture.example.test", new[] { HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { IncludeTakeoverCname = true })));
    }

    private sealed class Handler : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html></html>") });
    }
}
