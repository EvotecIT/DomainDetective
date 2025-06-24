using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByStringNS() {
        var nsRecord = "ns1.example.com";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckNS(nsRecord);
        Helpers.ShowPropertiesTable("NS Example by String", healthCheck.NSAnalysis);
    }

    public static async Task ExampleAnalyseByArrayNS() {
        var nsRecords = new List<string> { "ns1.example.com", "ns2.example.com" };
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckNS(nsRecords);
        Helpers.ShowPropertiesTable("NS Example by Array", healthCheck.NSAnalysis);
    }

    public static async Task ExampleAnalyseByDomainNS() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.NS });
        Helpers.ShowPropertiesTable("NS Example by Domain", healthCheck.NSAnalysis);
    }
}