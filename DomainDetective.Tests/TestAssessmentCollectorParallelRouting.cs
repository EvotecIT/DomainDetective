using DnsClientX;

namespace DomainDetective.Tests;

public class TestAssessmentCollectorParallelRouting {
    [Fact]
    public async Task ConcurrentAnalysesDoNotCaptureEachOthersAssessments() {
        var logger = new InternalLogger();
        var queryStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseQuery = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var mx = new MXAnalysis { Subject = "example.com" };
        mx.QueryDnsOverride = async (_, type) => {
            if (type == DnsRecordType.CNAME) {
                queryStarted.TrySetResult(true);
                await releaseQuery.Task;
            }
            return Array.Empty<DnsAnswer>();
        };
        mx.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());

        var mxTask = mx.AnalyzeMxRecords(new[] {
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 mail.example.com" }
        }, logger);
        try {
            var started = await Task.WhenAny(queryStarted.Task, Task.Delay(TimeSpan.FromSeconds(10)));
            Assert.Same(queryStarted.Task, started);

            var dane = new DANEAnalysis();
            await dane.AnalyzeDANERecords(new[] {
                new DnsAnswer {
                    Name = "_443._tcp.example.com",
                    Type = DnsRecordType.TLSA,
                    DataRaw = "3 1 1 " + new string('0', 64)
                }
            }, logger);

            Assert.Contains(dane.Assessments, assessment => assessment.Code == DaneCodes.RecordValid);
            Assert.DoesNotContain(mx.Assessments, assessment => assessment.Code == DaneCodes.RecordValid);
        } finally {
            releaseQuery.TrySetResult(true);
            await mxTask;
        }
    }
}
