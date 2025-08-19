using System.Collections.Generic;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestDkimAnalysisNoTxt {
    [Fact]
    public async Task DkimRecordExistsFalseWhenOnlySoaReturned() {
        var answers = new List<DnsAnswer> {
            new() { DataRaw = "ns.example.com hostmaster.example.com 1 7200 3600 1209600 3600", Type = DnsRecordType.SOA }
        };
        var analysis = new DkimAnalysis();
        await analysis.AnalyzeDkimRecords("selector", answers, new InternalLogger());
        var result = analysis.AnalysisResults["selector"];
        Assert.False(result.DkimRecordExists);
        Assert.Null(result.DkimRecord);
    }

    [Fact]
    public async Task AdspRecordIgnoredWhenOnlySoaReturned() {
        var answers = new List<DnsAnswer> {
            new() { DataRaw = "ns.example.com hostmaster.example.com 1 7200 3600 1209600 3600", Type = DnsRecordType.SOA }
        };
        var logger = new InternalLogger();
        var warnings = new List<LogEventArgs>();
        logger.OnWarningMessage += (_, e) => warnings.Add(e);
        var analysis = new DkimAnalysis();
        await analysis.AnalyzeAdspRecord(answers, logger);
        Assert.False(analysis.AdspRecordExists);
        Assert.Null(analysis.AdspRecord);
        Assert.Empty(warnings);
    }
}
