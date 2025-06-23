using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task Main() {
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
        await ExampleAnalyseSecurityTXT();
        await ExampleAnalyseDnsPropagation();
        await ExampleAnalyseDnsPropagationRegions();

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
