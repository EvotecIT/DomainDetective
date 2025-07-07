using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Example verifying a DKIM record from a raw string.
    /// </summary>
    public static async Task ExampleAnalyseByStringDKIM() {
        var dkimRecord = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckDKIM(dkimRecord);
        //foreach (var selector in healthCheck.DKIMAnalysis.AnalysisResults.Keys) {
        //    ShowProperties($"DKIM for EXAMPLE1 {dkimRecord} [Selector: {selector}]", healthCheck.DKIMAnalysis.AnalysisResults[selector]);
        //}
        Helpers.ShowPropertiesTable(analysisOf: "DKIM for EXAMPLE by String", objs: healthCheck.DKIMAnalysis.AnalysisResults);
    }

    /// <summary>
    /// Example performing DKIM check by querying a domain.
    /// </summary>
    public static async Task ExampleAnalyseByDomainDKIM() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DKIM }, new[] { "selector1", "selector2" });
        //foreach (var selector in healthCheck.DKIMAnalysis.AnalysisResults.Keys) {
        //    ShowProperties($"DKIM for evotec.pl [Selector: {selector}]", healthCheck.DKIMAnalysis.AnalysisResults[selector]);
        //}
        Helpers.ShowPropertiesTable(analysisOf: "DKIM for evotec.pl", objs: healthCheck.DKIMAnalysis.AnalysisResults);
    }
}