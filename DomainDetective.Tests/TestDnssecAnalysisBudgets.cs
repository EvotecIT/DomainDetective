using DnsClientX;

namespace DomainDetective.Tests;

public class TestDnssecAnalysisBudgets {
    [Fact]
    public async Task PublicAnalysisAppliesQueryDeadlineAndObservesCallbacks() {
        int active = 0;
        int canceled = 0;
        using var configuration = new DnsConfiguration {
            DnsSecQueryTimeout = TimeSpan.FromMilliseconds(20),
            QueryDnsResponseOverride = async (_, _, ct) => {
                Interlocked.Increment(ref active);
                try {
                    await Task.Delay(Timeout.Infinite, ct);
                    return new DnsResponse();
                } catch (OperationCanceledException) {
                    Interlocked.Increment(ref canceled);
                    throw;
                } finally { Interlocked.Decrement(ref active); }
            }
        };
        var analysis = new DnsSecAnalysis();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await analysis.Analyze("example.com", new InternalLogger(), configuration, guard.Token);
        Assert.True(canceled >= 4);
        Assert.Equal(0, active);
        Assert.False(analysis.ChainValid);
        Assert.Equal(DnssecValidationStatus.Indeterminate, analysis.ValidationStatus);
        Assert.False(analysis.MetadataQueriesComplete);
        Assert.NotEmpty(analysis.MetadataQueryFailures);
    }

    [Fact]
    public async Task WholeAnalysisDeadlineStopsMetadataAdmission() {
        var queried = new List<DnsRecordType>();
        using var configuration = new DnsConfiguration {
            DnsSecQueryTimeout = TimeSpan.FromSeconds(3),
            DnsSecAnalysisTimeout = TimeSpan.FromMilliseconds(60),
            QueryDnsResponseOverride = async (_, type, ct) => {
                queried.Add(type);
                if (type == DnsRecordType.SOA) { return new DnsResponse { Status = DnsResponseCode.NoError }; }
                await Task.Delay(Timeout.Infinite, ct);
                return new DnsResponse();
            }
        };
        var analysis = new DnsSecAnalysis();
        await analysis.Analyze("example.com", new InternalLogger(), configuration);
        // The analysis deadline can expire before DNSKEY obtains admission on a busy
        // host. Only this prefix may start; later metadata must not be admitted.
        Assert.InRange(queried.Count, 0, 2);
        Assert.Equal(new[] { DnsRecordType.SOA, DnsRecordType.DNSKEY }.Take(queried.Count), queried);
        Assert.False(analysis.MetadataQueriesComplete);
        Assert.Contains(analysis.MetadataQueryFailures, error => error.Contains("analysis budget"));
        Assert.False(analysis.ChainValid);
    }

    [Fact]
    public async Task CallerCancellationPropagatesAfterOwnedCallbackCompletes() {
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool finished = false;
        using var configuration = new DnsConfiguration {
            QueryDnsResponseOverride = async (_, _, ct) => {
                started.SetResult(true);
                try { await Task.Delay(Timeout.Infinite, ct); }
                finally { finished = true; }
                return new DnsResponse();
            }
        };
        using var cancellation = new CancellationTokenSource();
        var analysis = new DnsSecAnalysis();
        var work = analysis.Analyze("example.com", new InternalLogger(), configuration, cancellation.Token);
        await started.Task;
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => work);
        Assert.True(finished);
        Assert.False(analysis.ChainValid);
    }
}
