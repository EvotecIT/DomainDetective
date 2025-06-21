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

        await ExampleAnalyseByDomainCAA();
        await ExampleAnalyseByStringCAA();
        await ExampleAnalyseByListCAA();

        await ExampleCertificateVerification();
        await ExampleCertificateVerificationByHealthCheck();


        await ExampleAnalyseByDomainDANE();
        await ExampleAnalyseByStringDANE();

        await ExampleAnalyseByStringDNSBL();
        await ExampleAnalyseByArrayDNSBL();
        await ExampleAnalyseByDomainDNSBL();
        await ExampleAnalyseSecurityTXT();

        //await ExampleQueryDNS();
        //await ExampleAnalyseByStringWHOIS();
    }
}
