using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseByDnsSPF() {
        // Test SPF by querying DNS
        var healthCheck = new DomainHealthCheck();
        await healthCheck.Verify("github.com", [HealthCheckType.SPF]);
        //ShowProperties("Domain analysis of github.com", healthCheck.SpfAnalysis);
        Helpers.ShowPropertiesTable("Domain analysis of github.com", healthCheck.SpfAnalysis);

        var healthCheck3 = new DomainHealthCheck();
        await healthCheck3.Verify("microsoft.com", [HealthCheckType.SPF]);
        //ShowProperties("DOMAIN microsoft.com", healthCheck3.SpfAnalysis);
        Helpers.ShowPropertiesTable("DOMAIN microsoft.com", healthCheck3.SpfAnalysis);

        var healthCheck2 = new DomainHealthCheck();
        await healthCheck2.Verify("evotec.pl", [HealthCheckType.SPF]);
        //ShowProperties("DOMAIN evotec.pl", healthCheck2.SpfAnalysis);
        Helpers.ShowPropertiesTable("DOMAIN evotec.pl", healthCheck2.SpfAnalysis);
    }

    public static async Task ExampleAnalyseByStringSPF() {
        // Test SPF by string
        var spfRecord = "v=spf1 include:_spf.github.com ~all";
        var healthCheck1 = new DomainHealthCheck();
        await healthCheck1.CheckSPF(spfRecord);
        //ShowProperties("SPF for EXAMPLE.COM " + spfRecord, healthCheck1.SpfAnalysis);
        Helpers.ShowPropertiesTable("SPF for EXAMPLE.COM " + spfRecord, healthCheck1.SpfAnalysis);

        var spfRecord1 = "v=spf1 a mx include:spf.protection.outlook.com -all";
        var healthCheck4 = new DomainHealthCheck();
        await healthCheck4.CheckSPF(spfRecord1);
        //ShowProperties("SPF for EVOTEC.PL " + spfRecord1, healthCheck4.SpfAnalysis);
        Helpers.ShowPropertiesTable("SPF for EVOTEC.PL " + spfRecord1, healthCheck4.SpfAnalysis);

        var spfRecord2 = "v=spf1 ip4:207.68.169.173/30 ip4:207.68.176.1/26 ip4:207.46.132.129/27 ip4:207.68.176.97/27 ip4:65.55.238.129/26 ip4:207.46.222.193/26 ip4:207.46.116.135/29 ip4:65.55.178.129/27 ip4:213.199.161.129/27 ip4:65.55.33.70/28 ~all";
        var healthCheck5 = new DomainHealthCheck();
        await healthCheck5.CheckSPF(spfRecord2);
        //ShowProperties("SPF for EXAMPLE1 " + spfRecord2, healthCheck5.SpfAnalysis);
        Helpers.ShowPropertiesTable("SPF for EXAMPLE1 " + spfRecord2, healthCheck5.SpfAnalysis);

        var spfRecord3 = "v=spf1 a:google.com a:test.com ip4: include: test.example.pl include:_spf.salesforce.com include:_spf.google.com include:spf.protection.outlook.com include:_spf-a.example.com include:_spf-b.example.com include:_spf-c.example.com include:_spf-ssg-a.example.com include:spf-a.anotherexample.com ip4:131.107.115.215 ip4:131.107.115.214 ip4:205.248.106.64 ip4:205.248.106.30 ip4:205.248.106.32 ~all";
        var healthCheck6 = new DomainHealthCheck();
        healthCheck6.Verbose = true;
        await healthCheck6.CheckSPF(spfRecord3);
        //ShowProperties("SPF for EXAMPLE1 " + spfRecord3, healthCheck6.SpfAnalysis);
        Helpers.ShowPropertiesTable("SPF for EXAMPLE1 " + spfRecord3, healthCheck6.SpfAnalysis);
    }
}