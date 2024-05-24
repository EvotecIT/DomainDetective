using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByStringWHOIS() {
        string[] domainNames = [
            //"evotec.xyz",
            //"evotec.pl",
            //"evotec.com",
            //"evotec.net",
            //"google.com",
            "google.co.uk",
            "evotec.be",
            "evotec.cz",
            //"evotec.de",
        ];
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        foreach (var domain in domainNames) {
            await healthCheck.CheckWHOIS(domain);
            Helpers.ShowPropertiesTable(analysisOf: $"WHOIS for {domain}", objs: healthCheck.WhoisAnalysis);
        }
    }

    public static async Task ExampleAnalyseByDomainWHOIS() {
        //var healthCheck = new DomainHealthCheck();
        //healthCheck.Verbose = false;
        //await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DKIM }, new[] { "selector1", "selector2" });
        ////foreach (var selector in healthCheck.DKIMAnalysis.AnalysisResults.Keys) {
        ////    ShowProperties($"DKIM for evotec.pl [Selector: {selector}]", healthCheck.DKIMAnalysis.AnalysisResults[selector]);
        ////}
        //Helpers.ShowPropertiesTable(analysisOf: "DKIM for evotec.pl", objs: healthCheck.DKIMAnalysis.AnalysisResults);
    }
}
