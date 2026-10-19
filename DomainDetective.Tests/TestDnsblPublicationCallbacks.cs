using DnsClientX;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestDnsblPublicationCallbacks {
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ListedAppendsNotifyEachLoggerAndRetainDistinctAddressAssessments(bool overlapping, bool distinctAddress) {
        using var configuration = new DnsConfiguration();
        var analysis = new DNSBLAnalysis(configuration);
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int queries = 0;
        configuration.QueryDnsResponseOverride = async (owner, type, token) => {
            if (overlapping && Interlocked.Increment(ref queries) == 1) {
                entered.TrySetResult(true);
                await release.Task.WaitWithCancellation(token);
            }
            return new DnsResponse { Status = DnsResponseCode.NoError,
                Answers = new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "127.0.0.2" } } };
        };
        var loggers = new[] { new InternalLogger(), new InternalLogger() };
        var warnings = new[] { new List<string>(), new List<string>() };
        loggers[0].OnWarningMessage += (_, entry) => { if (entry.Code == DnsblCodes.Listed) { warnings[0].Add(entry.FullMessage); } };
        loggers[1].OnWarningMessage += (_, entry) => { if (entry.Code == DnsblCodes.Listed) { warnings[1].Add(entry.FullMessage); } };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var first = analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, loggers[0], false, guard.Token);
        try {
            if (overlapping) { await entered.Task.WaitWithCancellation(guard.Token); }
            else { await first; }
            await analysis.AnalyzeDNSBLRecordsMany(new[] { distinctAddress ? "192.0.2.2" : "192.0.2.1" }, loggers[1], false, guard.Token);
        } finally {
            release.TrySetResult(true);
            await first;
        }
        Assert.All(warnings, items => Assert.Single(items));
        Assert.Equal(2, analysis.AllResults.Count);
        Assert.All(analysis.AllResults, record => Assert.True(record.IsBlackListed));
        var listed = analysis.Assessments.Where(item => item.Code == DnsblCodes.Listed).ToArray();
        Assert.Equal(distinctAddress ? 2 : 1, listed.Length);
        Assert.Contains(listed, item => item.Target == "192.0.2.1");
        if (distinctAddress) { Assert.Contains(listed, item => item.Target == "192.0.2.2"); }
    }

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
