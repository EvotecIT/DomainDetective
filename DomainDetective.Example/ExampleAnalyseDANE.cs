using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByStringDANE() {
        var daneRecord = "3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B566 64C5D3D6";
        var healthCheck = new DomainHealthCheck {
            Verbose = false
        };
        await healthCheck.CheckDANE(daneRecord);
        Helpers.ShowPropertiesTable(analysisOf: "DANE Example by String", objs: healthCheck.DaneAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "DANE Example by String", objs: healthCheck.DaneAnalysis.AnalysisResults);
        var narrative = DaneNarrative.Build(healthCheck.DaneAnalysis, healthCheck.DaneAnalysis.Assessments);
        System.Console.WriteLine(narrative.Title);
        foreach (var h in narrative.Highlights) System.Console.WriteLine(" - " + h);
    }

    public static async Task ExampleAnalyseByDomainDANE() {
        var healthCheck = new DomainHealthCheck {
            Verbose = false
        };
        await healthCheck.Verify("ietf.org", new[] { HealthCheckType.DANE });
        Helpers.ShowPropertiesTable(analysisOf: "DANE Example Record", objs: healthCheck.DaneAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "DANE Example Record", objs: healthCheck.DaneAnalysis.AnalysisResults);
    }

    public static async Task ExampleAnalyseByDomainDANE1() {
        var healthCheck = new DomainHealthCheck {
            Verbose = false
        };
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DANE });
        Helpers.ShowPropertiesTable(analysisOf: "DANE Example Record", objs: healthCheck.DaneAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "DANE Example Record", objs: healthCheck.DaneAnalysis.AnalysisResults);
    }
}