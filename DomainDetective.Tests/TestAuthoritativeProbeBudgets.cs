using DnsClientX;
using DomainDetective.Helpers;
using System.Net;

namespace DomainDetective.Tests;

public class TestAuthoritativeProbeBudgets {
    [Fact]
    public async Task SuccessfulEmptyAddressAndNsResponsesDoNotEstablishNonexistence() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        health.MXAnalysis.Subject = "example.test";
        await health.MXAnalysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 empty.example.test" } }, new InternalLogger());
        Assert.False(health.MXAnalysis.PointsToNonExistentDomain);
        Assert.True(health.MXAnalysis.PointsToDomainWithoutAOrAaaaRecord);
        Assert.False(health.MXAnalysis.AddressQueryFailed);
    }

    [Theory]
    [InlineData(DnsRecordType.A)]
    [InlineData(DnsRecordType.AAAA)]
    [InlineData(DnsRecordType.CNAME)]
    public async Task NxDomainRemainsConclusiveWhenAddressQueriesFail(DnsRecordType negativeFamily) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Status = type == negativeFamily ? DnsResponseCode.NXDomain :
                type == DnsRecordType.A || type == DnsRecordType.AAAA ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError
        });
        health.MXAnalysis.Subject = "example.test";
        await health.MXAnalysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 missing.example.test" } }, new InternalLogger());
        Assert.True(health.MXAnalysis.PointsToNonExistentDomain);
        Assert.True(health.MXAnalysis.AddressQueryFailed);
        var evaluated = DomainDetective.DesiredState.DesiredStateEvaluator.Evaluate("example.test", health,
            new DomainDetective.DesiredState.DesiredStateProfile { Mx = new DomainDetective.DesiredState.DesiredStateMxPolicy { DisallowNonExistentTargets = true } });
        Assert.Contains(evaluated.Assessments, item => item.Code == DomainDetective.DesiredState.DesiredStateCodes.MxTargetNonExistent);
        Assert.DoesNotContain(evaluated.Assessments, item => item.Code == "DesiredState.MX.Address.QueryFailed");
    }

    [Fact]
    public void MxCompletenessUsesTheExistingCollectorWithoutDuplicateAssessments() {
        var analysis = new MXAnalysis();
        var logger = new InternalLogger();
        using var collector = AssessmentCollector.ForAnalysis(logger, analysis, category: "MX");
        analysis.RecordRrsetCompleteness(2, 1, "example.test", logger, collector);
        analysis.RecordTargetAddressEvidence("mail.example.test", Array.Empty<(DnsResponse? A, DnsResponse? Aaaa)>(), logger, collector);
        analysis.RecordRrsetConsistency("example.test", new[] {
            new HashSet<string> { "10 first.example.test" }, new HashSet<string> { "20 second.example.test" }
        }, logger, collector);
        Assert.Equal("example.test", Assert.Single(analysis.Assessments, item => item.Code == "MX.Rrset.ComparisonIncomplete").Target);
        Assert.Equal("mail.example.test", Assert.Single(analysis.Assessments, item => item.Code == "MX.TargetAddress.ComparisonIncomplete").Target);
        Assert.Equal("example.test", Assert.Single(analysis.Assessments, item => item.Code == MxCodes.RrsetInconsistentAcrossNs).Target);
        Assert.Equal(1, DomainDetective.Views.Converters.Convert(analysis).WarningCount);
    }

    [Theory]
    [InlineData(DnsRecordType.A, false)]
    [InlineData(DnsRecordType.AAAA, false)]
    [InlineData(DnsRecordType.NS, false)]
    [InlineData(DnsRecordType.A, true)]
    [InlineData(DnsRecordType.AAAA, true)]
    [InlineData(DnsRecordType.NS, true)]
    public async Task FailedRecursiveMxLookupsRemainUnknownWithoutLosingOtherHosts(DnsRecordType failedType, bool envelope) {
        using var health = new DomainHealthCheck();
        var analysis = health.MXAnalysis;
        analysis.Subject = "example.test";
        Func<string, DnsRecordType, Task<DnsAnswer[]>> answers = (host, type) => {
            if (host == "bad.example.test" && type == failedType) { throw new TimeoutException("Target query failed."); }
            bool address = type == DnsRecordType.A && (host == "good.example.test" || failedType != DnsRecordType.NS);
            return Task.FromResult(address ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>());
        };
        analysis.QueryDnsOverride = answers;
        if (envelope) {
            analysis.QueryDnsOverride = null;
            health.DnsConfiguration.QueryDnsResponseOverride = async (host, type, _) => {
                try { return new DnsResponse { Status = DnsResponseCode.NoError, Answers = await answers(host, type) }; }
                catch (TimeoutException) { return new DnsResponse { Status = DnsResponseCode.ServerFailure }; }
            };
        }
        await analysis.AnalyzeMxRecords(new[] {
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 bad.example.test" },
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "20 good.example.test" }
        }, new InternalLogger());
        Assert.True(analysis.AddressQueryFailed);
        Assert.False(analysis.ValidMxConfiguration);
        Assert.False(analysis.PointsToNonExistentDomain);
        Assert.Contains(analysis.Assessments, item => item.Code == "MX.Address.QueryFailed");
        Assert.True(DomainDetective.Views.Converters.Convert(analysis).AddressQueryFailed);
        var evaluated = DomainDetective.DesiredState.DesiredStateEvaluator.Evaluate("example.test", health,
            new DomainDetective.DesiredState.DesiredStateProfile { Mx = new DomainDetective.DesiredState.DesiredStateMxPolicy { DisallowNonExistentTargets = true, RequireIpv6Supported = true } });
        Assert.Contains(evaluated.Assessments, item => item.Code == "DesiredState.MX.Address.QueryFailed");
    }

    [Theory]
    [InlineData(DnsResponseCode.NoError, false, true)]
    [InlineData(DnsResponseCode.Refused, false, false)]
    [InlineData(DnsResponseCode.Refused, true, true)]
    [InlineData(DnsResponseCode.ServerFailure, true, false)]
    public void RefusalEstablishesReachabilityOnlyForThePreflight(DnsResponseCode status, bool preflight, bool accepted) {
        var response = new DnsResponse { Status = status };
        Assert.Equal(accepted, AuthoritativeDnsProbes.IsUsableResponse(response, preflight));
        response.Error = "Response was not decoded successfully.";
        Assert.False(AuthoritativeDnsProbes.IsUsableResponse(response, preflight));
    }

    [Theory]
    [InlineData(DnsResponseCode.ServerFailure)]
    [InlineData(DnsResponseCode.Refused)]
    public async Task FailedMxAliasResponseCannotEstablishAnAliasFreeTarget(DnsResponseCode failure) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Status = type == DnsRecordType.CNAME ? failure : DnsResponseCode.NoError,
            Answers = type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>()
        });
        var analysis = health.MXAnalysis;
        analysis.Subject = "example.test";
        await analysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "0 mail.example.test" } }, new InternalLogger());
        Assert.True(analysis.CnameQueryFailed);
        // Isolate alias coverage from independently completed authoritative comparisons.
        analysis.RecordRrsetCompleteness(1, 1, "example.test", new InternalLogger());
        typeof(MXAnalysis).GetProperty(nameof(MXAnalysis.TargetAddressComparisonIncomplete))!.SetValue(analysis, false);
        Assert.Equal("Incomplete", DomainDetective.Views.Converters.Convert(analysis).Status);
        Assert.False(analysis.ValidMxConfiguration);
        Assert.False(analysis.PointsToNonExistentDomain);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task PartialAuthoritativeResponsesRetainSuccessfulFamilyEvidence(bool failA, bool different) {
        DnsResponse Reply(DnsRecordType type, string value) => new() {
            IsAuthoritativeAnswer = true,
            Answers = new[] { new DnsAnswer { Type = type, DataRaw = value } }
        };
        using var health = new DomainHealthCheck();
        var analysis = health.MXAnalysis;
        analysis.Subject = "example.test";
        analysis.QueryDnsOverride = (_, recordType) => Task.FromResult(recordType == DnsRecordType.A
            ? new[] { new DnsAnswer { Type = recordType, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>());
        await analysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "0 mail.example.test" } }, new InternalLogger());
        var type = failA ? DnsRecordType.AAAA : DnsRecordType.A;
        var first = Reply(type, failA ? "2001:db8::1" : "192.0.2.1");
        var second = different ? Reply(type, failA ? "2001:db8::2" : "192.0.2.2") : first;
        var empty = new DnsResponse { IsAuthoritativeAnswer = true };
        analysis.RecordTargetAddressEvidence("mail.example.test", failA
            ? new (DnsResponse? A, DnsResponse? Aaaa)[] { (null, first), (empty, second) }
            : new (DnsResponse? A, DnsResponse? Aaaa)[] { (first, null), (second, empty) }, new InternalLogger());
        Assert.Equal(!different, analysis.TargetAddressConsistentAcrossNs);
        Assert.True(analysis.TargetAddressComparisonIncomplete);
        Assert.True(DomainDetective.Views.Converters.Convert(analysis).TargetAddressComparisonIncomplete);
        Assert.Equal(different, analysis.Assessments.Any(item => item.Code == MxCodes.TargetAddressInconsistentAcrossNs));
        var desired = DomainDetective.DesiredState.DesiredStateEvaluator.Evaluate("example.test", health,
            new DomainDetective.DesiredState.DesiredStateProfile {
                Mx = new DomainDetective.DesiredState.DesiredStateMxPolicy { RequireTargetAddressConsistentAcrossNs = true }
            });
        Assert.False(desired.Conforms);
        Assert.Contains(desired.Assessments, item => item.Code == "DesiredState.MX.TargetAddress.QueryFailed");
    }

    [Fact]
    public async Task UniformityPhaseRetainsItsDiagnosticsAfterTheInitialAnalysis() {
        using var health = new DomainHealthCheck();
        var analysis = health.DnsTtlAnalysis;
        var logger = new InternalLogger();
        analysis.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        await analysis.Analyze("example.test", logger);
        analysis.QueryDnsOverride = (_, _) => {
            AuthoritativeDnsProbes.ReportIpv6Reachability(new[] { "192.0.2.1", "2001:db8::1" }, new[] { "192.0.2.1" }, logger);
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };
        await analysis.AnalyzeUniformityAcrossServers("example.test", logger);
        Assert.Contains(analysis.Assessments, item => item.Code == "DNS.Authoritative.IPv6.NoUsableResponse");
        Assert.Contains(health.GetAllAssessments(), item => item.Code == "DNS.Authoritative.IPv6.NoUsableResponse");
    }

    [Fact]
    public async Task LateOverrideIsObservedButItsAnswerCannotOutliveTheValidationBudget() {
        var expired = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var configuration = new DnsConfiguration { DnsSecQueryTimeout = TimeSpan.FromMilliseconds(20),
            QueryDnsResponseOverride = async (_, _, token) => {
                using var registration = token.Register(() => expired.TrySetResult(true));
                await release.Task;
                return new DnsResponse { Answers = new[] { new DnsAnswer { Type = DnsRecordType.TLSA, DataRaw = "late answer" } } };
            } };
        var run = DnsSecAnalysis.QueryValidatedSubjectResponseAsync("_443._tcp.example.test", DnsRecordType.TLSA, configuration, default);
        try {
            await expired.Task.WaitWithCancellation(guard.Token);
            Assert.False(run.IsCompleted);
        } finally { release.TrySetResult(true); }
        var response = await run;
        Assert.Equal(DnsResponseCode.ServerFailure, response.Status);
        Assert.Empty(response.Answers);
    }

    [Fact]
    public async Task SlowMxAliasLookupRetainsAddressEvidenceAndReportsUnknownAliasStatus() {
        using var health = new DomainHealthCheck();
        var analysis = health.MXAnalysis;
        analysis.Subject = "example.test";
        analysis.QueryDnsOverride = async (name, type) => {
            if (type == DnsRecordType.CNAME) {
                await Task.Delay(3000);
                return new[] { new DnsAnswer { Type = type, DataRaw = "alias.example.test" } };
            }
            return type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>();
        };
        await analysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "0 mail.example.test" } }, new InternalLogger());
        Assert.True(analysis.CnameQueryFailed);
        Assert.False(analysis.PointsToCname);
        Assert.False(analysis.PointsToNonExistentDomain);
        Assert.True(DomainDetective.Views.Converters.Convert(analysis).CnameQueryFailed);
        Assert.False(analysis.ValidMxConfiguration);
        Assert.False(analysis.ValidateMxConfiguration());
        Assert.Contains(analysis.Assessments, a => a.Code == "MX.Cname.QueryFailed");
        var desired = DomainDetective.DesiredState.DesiredStateEvaluator.Evaluate("example.test", health,
            new DomainDetective.DesiredState.DesiredStateProfile {
                Mx = new DomainDetective.DesiredState.DesiredStateMxPolicy { DisallowCnameTargets = true }
            });
        Assert.False(desired.Conforms);
        Assert.Contains(desired.Assessments, a => a.Code == "DesiredState.MX.Cname.QueryFailed");
    }
    [Fact]
    public async Task ValidatedQueryBudgetRetainsUnknownRatherThanClaimingAbsentRecords() {
        using var configuration = new DnsConfiguration { DnsSecQueryTimeout = TimeSpan.FromMilliseconds(50) };
        configuration.QueryDnsResponseOverride = async (_, _, token) => {
            await Task.Delay(Timeout.Infinite, token);
            return new DnsResponse();
        };
        var response = await DnsSecAnalysis.QueryValidatedSubjectResponseAsync("_443._tcp.example.test", DnsRecordType.TLSA, configuration, default);
        Assert.Equal(DnsResponseCode.ServerFailure, response.Status);
        Assert.Contains("budget exhausted", response.Error);
        Assert.Empty(response.Answers);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DnsSecAnalysis.QueryValidatedSubjectResponseAsync("_443._tcp.example.test", DnsRecordType.TLSA, configuration, canceled.Token));
    }

    [Fact]
    public async Task NameServerEnrichmentRunsConcurrentlyAndRetainsEveryAnswer() {
        var admitted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int started = 0;
        var analysis = new NSAnalysis { Subject = "example.test", EnableChaosFingerprinting = false,
            QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" }, new DnsAnswer { Type = type, DataRaw = "192.0.2.2" } }
                : Array.Empty<DnsAnswer>()),
            LookupAsnOverride = async address => {
                if (Interlocked.Increment(ref started) == 2) { admitted.TrySetResult(true); }
                await release.Task;
                return address.EndsWith("1", StringComparison.Ordinal) ? 64512 : 64513;
            } };
        var run = analysis.AnalyzeNsRecords(new[] { new DnsAnswer { Type = DnsRecordType.NS, DataRaw = "ns.example.test" } }, new InternalLogger());
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await admitted.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); }
        await run;
        Assert.Equal(2, analysis.AsnByIp.Count);
        Assert.Equal(2, analysis.AsnDistinctCount);
    }

    [Fact]
    public void Ipv6ReachabilityNoteRequiresIpv4EvidenceAndNoIpv6Replies() {
        var logger = new InternalLogger();
        var analysis = new NSAnalysis();
        using var collector = AssessmentCollector.ForAnalysis(logger, analysis);
        var addresses = new[] { "192.0.2.1", "2001:db8::1" };
        AuthoritativeDnsProbes.ReportIpv6Reachability(addresses, new[] { "192.0.2.1" }, logger);
        var note = Assert.Single(analysis.Assessments);
        Assert.Equal("DNS.Authoritative.IPv6.NoUsableResponse", note.Code);
        Assert.Equal(AssessmentSeverity.Info, note.Severity);
        AuthoritativeDnsProbes.ReportIpv6Reachability(addresses, Array.Empty<string>(), logger);
        AuthoritativeDnsProbes.ReportIpv6Reachability(addresses, addresses, logger);
        Assert.Single(analysis.Assessments);
    }
}
