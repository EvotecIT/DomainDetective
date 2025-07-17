using DomainDetective;
using System;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task Main(string[] args) {
        if (args.Length > 0 && args.Any(a => !a.StartsWith("-"))) {
            var outputJson = args.Contains("--json");
            var domain = args.First(a => !a.StartsWith("-"));
            try {
                domain = DomainHelper.ValidateIdn(domain);
            } catch (ArgumentException) {
            }
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
        await ExampleFlattenSpfIps();

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
        await ExampleCertificateExpiration();

        await ExampleAnalyseHTTP();
        await ExampleAnalyseHTTPByHealthCheck();
        await ExampleDetectUnsafeCsp();


        await ExampleAnalyseByDomainDANE();
        await ExampleAnalyseByStringDANE();

        await ExampleAnalyseByStringDNSBL();
        await ExampleAnalyseByArrayDNSBL();
        await ExampleAnalyseByDomainDNSBL();
        await ExampleManageDnsbl();
        await ExampleAnalyseOpenRelay();
        await ExampleAnalyseOpenResolver();
        await ExampleAnalyseSecurityTXT();
        await ExampleAnalyseDnsPropagation();
        await ExampleValidateServerAsn();
        await ExampleAnalyseDnsPropagationRegions();
        await ExampleAnalyseDnsTtl();
        await ExampleDomainSummary();
        await ExampleAnalyseThreatIntel();
        await ExampleAnalyseThreatFeed();
        await ExampleAnalyseTyposquatting();
        await ExampleAnalyseEdnsSupport();
        await ExampleAnalyseGeoIp();
        await ExamplePortScan();
        await ExampleAnalyseSNMP();
        await ExampleCtLogAggregator();
        await ExampleVirusTotalClient();
        await ExampleVirusTotalDirect();

        await ExampleCheckDomainAvailability();
        await ExampleCheckLabelAcrossTlds();
        await ExampleSuggestDomain();

        //await ExampleQueryDNS();
        //await ExampleAnalyseByStringWHOIS();
    }

    public static async Task ExampleAnalyseDnsPropagation() {
        await ExampleAnalyseDnsPropagationClass.Run();
    }

    public static async Task ExampleValidateServerAsn() {
        await ExampleValidateServerAsnClass.Run();
    }

    public static async Task ExampleAnalyseDnsPropagationRegions() {
        await ExampleAnalyseDnsPropagationRegionsClass.Run();
    }
}