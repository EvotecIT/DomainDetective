using DnsClient.Protocol;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByStringCAA() {
        var caaRecord = "128 issue letsencrypt.org";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckCAA(caaRecord);
        //foreach (var analysis in healthCheck.CAAAnalysis.AnalysisResults) {
        //    ShowProperties("CAA Example Record", analysis);
        //}
        Helpers.ShowPropertiesTable(analysisOf: "CAA Example by String", objs: healthCheck.CAAAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "CAA Example by String", objs: healthCheck.CAAAnalysis.AnalysisResults);
    }

    public static async Task ExampleAnalyseByListCAA() {
        List<string> caaRecords = new List<string> {
            "0 issue \"digicert.com; cansignhttpexchanges=yes\"",
            "0 issue \"letsencrypt.org;validationmethods=dns-01\"",
            "0 issue \"pki.goog; cansignhttpexchanges=yes\"",
            "0 issuewild \"letsencrypt.org\"",
            "0 issue \"letsencrypt.org\"",
            "0 iodef \"mailto:example@example.com\"",
            "260 issue \";\"",
            "0 issue \"letsencrypt.org\"",
            "0 issuemail \";\""
        };
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckCAA(caaRecords);
        Helpers.ShowPropertiesTable(analysisOf: "CAA Example by String", objs: healthCheck.CAAAnalysis);

        Helpers.ShowPropertiesTable(analysisOf: "CAA Example by String", objs: healthCheck.CAAAnalysis.AnalysisResults);
    }

    public static async Task ExampleAnalyseByDomainCAA() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.CAA });
        //foreach (var analysis in healthCheck.CAAAnalysis.AnalysisResults) {
        //    ShowProperties("CAA Example Record", analysis);
        //}
        Helpers.ShowPropertiesTable(analysisOf: "CAA Example Record", objs: healthCheck.CAAAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "CAA Example Record", objs: healthCheck.CAAAnalysis.AnalysisResults);
    }
}
