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
        Helpers.ShowPropertiesTable(analysisOf: "CAA Example by String", objs: healthCheck.CAAAnalysis.AnalysisResults);
    }

    public static async Task ExampleAnalyseByDomainCAA() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.CAA });
        //foreach (var analysis in healthCheck.CAAAnalysis.AnalysisResults) {
        //    ShowProperties("CAA Example Record", analysis);
        //}
        Helpers.ShowPropertiesTable(analysisOf: "CAA Example Record", objs: healthCheck.CAAAnalysis.AnalysisResults);
    }
}