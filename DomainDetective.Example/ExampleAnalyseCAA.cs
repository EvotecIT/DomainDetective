using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByStringCAA() {
        var caaRecord = "128 issue letsencrypt.org";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = true;
        await healthCheck.CheckCAA(caaRecord);
        foreach (var analysis in healthCheck.CAAAnalysis.AnalysisResults) {
            ShowProperties("CAA Example Record", analysis);
        }
    }

    public static async Task ExampleAnalyseByDomainCAA() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = true;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.CAA });
        foreach (var analysis in healthCheck.CAAAnalysis.AnalysisResults) {
            ShowProperties("CAA Example Record", analysis);
        }
    }
}