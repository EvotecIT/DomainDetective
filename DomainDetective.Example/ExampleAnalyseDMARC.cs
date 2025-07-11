using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Example analyzing a DMARC record provided as a string.
    /// </summary>
    public static async Task ExampleAnalyseByStringDMARC() {
        var dmarcRecord = "v=DMARC1; p=reject; rua=mailto:1012c7e7df7b474cb85c1c8d00cc1c1a@dmarc-reports.cloudflare.net,mailto:7kkoc19n@ag.eu.dmarcian.com,mailto:dmarc@evotec.pl; adkim=s; aspf=s;";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckDMARC(dmarcRecord);
        //ShowProperties("DMARC for EXAMPLE1 " + dmarcRecord, healthCheck.DmarcAnalysis);
        Helpers.ShowPropertiesTable("DMARC for string ", healthCheck.DmarcAnalysis);
    }
    /// <summary>
    /// Example performing DMARC analysis by querying a domain.
    /// </summary>
    public static async Task ExampleAnalyseByDomainDMARC() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("xn--bcher-kva.ch", [HealthCheckType.DMARC]);
        //ShowProperties("DMARC for bücher.ch ", healthCheck.DmarcAnalysis);
        Helpers.ShowPropertiesTable("DMARC for bücher.ch ", healthCheck.DmarcAnalysis);
    }
}
