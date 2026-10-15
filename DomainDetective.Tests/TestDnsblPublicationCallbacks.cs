using DnsClientX;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestDnsblPublicationCallbacks {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WarningSubscriberCanReadPublishedCoverageOnAnotherThread(bool discovery) {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Status = discovery ? DnsResponseCode.NXDomain : DnsResponseCode.ServerFailure }
        });
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        var logger = new InternalLogger();
        int callbacks = 0;
        logger.OnWarningMessage += (_, _) => {
            var read = Task.Factory.StartNew(() => Converters.Convert(analysis), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Assert.True(read.Wait(TimeSpan.FromSeconds(10)), "A logger subscriber could not read the published analysis.");
            Assert.Equal("Incomplete", read.Result.Status);
            Interlocked.Increment(ref callbacks);
        };
        if (discovery) { await analysis.AnalyzeDNSBLRecordsMX("example.test", logger, scanMode: DomainIpScanMode.MxAOnly); }
        else { await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, logger); }
        Assert.True(callbacks > 0);
    }

    [Fact]
    public async Task EachAppendKeepsItsOwnLoggerAndWarningAssessments() {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstLogger = new InternalLogger();
        var secondLogger = new InternalLogger();
        var firstWarnings = new List<string>();
        var secondWarnings = new List<string>();
        firstLogger.OnWarningMessage += (_, entry) => firstWarnings.Add(entry.FullMessage);
        secondLogger.OnWarningMessage += (_, entry) => secondWarnings.Add(entry.FullMessage);
        analysis.QueryDnsFullOverride = async (names, _) => {
            bool first = names[0].StartsWith("1.2.0.192.", StringComparison.Ordinal);
            if (first) { entered.TrySetResult(true); await release.Task; }
            return new[] { new DnsResponse { Status = DnsResponseCode.ServerFailure, Error = first ? "first caller" : "second caller" } };
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var firstRun = analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, firstLogger, false, guard.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.2" }, secondLogger, false, guard.Token);
        } finally { release.TrySetResult(true); }
        await firstRun;
        Assert.Contains(firstWarnings, item => item.Contains("first caller"));
        Assert.DoesNotContain(firstWarnings, item => item.Contains("second caller"));
        Assert.Contains(secondWarnings, item => item.Contains("second caller"));
        Assert.DoesNotContain(secondWarnings, item => item.Contains("first caller"));
        Assert.Contains(analysis.Assessments, item => item.Code == DnsblCodes.QueryFailed && item.Target == "192.0.2.1");
        Assert.Contains(analysis.Assessments, item => item.Code == DnsblCodes.QueryFailed && item.Target == "192.0.2.2");
    }
}
