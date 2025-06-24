using System;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task Main(string[] args) {
        if (args.Length > 0 && args.Any(a => !a.StartsWith("-"))) {
            var outputJson = args.Contains("--json");
            var domain = args.First(a => !a.StartsWith("-"));
            var healthCheck = new DomainHealthCheck();
            await healthCheck.Verify(domain);
            if (outputJson) {
                Console.WriteLine(healthCheck.ToJson());
            } else {
                Console.WriteLine($"Health check completed for {domain}");
            }
            return;
        }
        await ExampleAnalyseByDnsSPF();
        await ExampleAnalyseByStringSPF();

        await ExampleAnalyseByStringDMARC();
        await ExampleAnalyseByDomainDMARC();

        await ExampleAnalyseByStringDKIM();
        await ExampleAnalyseByDomainDKIM();

        await ExampleAnalyseMX();

        await ExampleAnalyseByStringNS();
        await ExampleAnalyseByArrayNS();
        await ExampleAnalyseByDomainNS();

        await ExampleAnalyseByDomainCAA();
        await ExampleAnalyseByStringCAA();
        await ExampleAnalyseByListCAA();

        await ExampleCertificateVerification();
        await ExampleCertificateVerificationByHealthCheck();

        await ExampleAnalyseHTTP();
        await ExampleAnalyseHTTPByHealthCheck();


        await ExampleAnalyseByDomainDANE();
        await ExampleAnalyseByStringDANE();

        await ExampleAnalyseByStringDNSBL();
        await ExampleAnalyseByArrayDNSBL();
        await ExampleAnalyseByDomainDNSBL();
        await ExampleManageDnsbl();
        await ExampleAnalyseOpenRelay();
        await ExampleAnalyseSecurityTXT();
        await ExampleAnalyseDnsPropagation();
        await ExampleAnalyseDnsPropagationRegions();
        await ExampleDomainSummary();

        //await ExampleQueryDNS();
        //await ExampleAnalyseByStringWHOIS();
    }

    public static async Task ExampleAnalyseDnsPropagation() {
        await ExampleAnalyseDnsPropagationClass.Run();
    }

    public static async Task ExampleAnalyseDnsPropagationRegions() {
        await ExampleAnalyseDnsPropagationRegionsClass.Run();
    }
}