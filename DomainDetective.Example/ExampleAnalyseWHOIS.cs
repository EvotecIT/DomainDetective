using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByStringWHOIS() {
        var domainName = "evotec.xyz";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckWHOIS(domainName);
        //foreach (var selector in healthCheck.DKIMAnalysis.AnalysisResults.Keys) {
        //    ShowProperties($"DKIM for EXAMPLE1 {dkimRecord} [Selector: {selector}]", healthCheck.DKIMAnalysis.AnalysisResults[selector]);
        //}

        Console.WriteLine(healthCheck.WhoisAnalysis.WhoisData);
        Console.WriteLine("----");
        domainName = "evotec.pl";
        await healthCheck.CheckWHOIS(domainName);
        Console.WriteLine(healthCheck.WhoisAnalysis.WhoisData);
        Console.WriteLine("----");
        domainName = "microsoft.com";
        await healthCheck.CheckWHOIS(domainName);
        Console.WriteLine(healthCheck.WhoisAnalysis.WhoisData);

        Console.WriteLine("----");
        domainName = "google.co.uk";
        await healthCheck.CheckWHOIS(domainName);
        Console.WriteLine(healthCheck.WhoisAnalysis.WhoisData);

        //Helpers.ShowPropertiesTable(analysisOf: "WHOIS for EXAMPLE by String", objs: healthCheck.WhoisAnalysis);
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
