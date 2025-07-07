using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates DNSBL analysis functions.
/// </summary>
public static partial class Program {
    /// <summary>Checks a single IP address or host.</summary>
    public static async Task ExampleAnalyseByStringDNSBL() {

        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckDNSBL("89.74.48.96");
        Helpers.ShowPropertiesTable(analysisOf: "DNSBL by String", objs: healthCheck.DNSBLAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "DNSBL by String", objs: healthCheck.DNSBLAnalysis.Results);
    }

    /// <summary>Checks multiple IP addresses or hosts.</summary>
    public static async Task ExampleAnalyseByArrayDNSBL() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckDNSBL(["89.74.48.96", "evotec.pl"]);
        Helpers.ShowPropertiesTable(analysisOf: "DNSBL by String", objs: healthCheck.DNSBLAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "DNSBL by String", objs: healthCheck.DNSBLAnalysis.Results);
    }


    /// <summary>Checks DNSBL status for a domain.</summary>
    public static async Task ExampleAnalyseByDomainDNSBL() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DNSBL });
        Helpers.ShowPropertiesTable(analysisOf: "DNSBL for evotec.pl", objs: healthCheck.DNSBLAnalysis);
        Helpers.ShowPropertiesTable(analysisOf: "DNSBL for evotec.pl", objs: healthCheck.DNSBLAnalysis.Results);
    }
}