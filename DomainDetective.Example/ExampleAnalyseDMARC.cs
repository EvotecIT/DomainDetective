using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByStringDMARC() {
        var dmarcRecord = "v=DMARC1; p=reject; rua=mailto:1012c7e7df7b474cb85c1c8d00cc1c1a@dmarc-reports.cloudflare.net,mailto:7kkoc19n@ag.eu.dmarcian.com,mailto:dmarc@evotec.pl; adkim=s; aspf=s;";
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckDMARC(dmarcRecord);
        //ShowProperties("DMARC for EXAMPLE1 " + dmarcRecord, healthCheck.DmarcAnalysis);
        Helpers.ShowPropertiesTable("DMARC for string ", healthCheck.DmarcAnalysis);
    }
    public static async Task ExampleAnalyseByDomainDMARC() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", [HealthCheckType.DMARC]);
        //ShowProperties("DMARC for evotec.pl ", healthCheck.DmarcAnalysis);
        Helpers.ShowPropertiesTable("DMARC for evotec.pl ", healthCheck.DmarcAnalysis);
    }
}
