using DomainDetective;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {

    public static async Task ExampleCertificateVerification() {
        var analysis = await CertificateAnalysis.CheckWebsiteCertificate("https://google.com");
        Helpers.ShowPropertiesTable("Certificate for google.com", analysis);
        Helpers.ShowPropertiesTable("Certificate for google.com", analysis.Certificate);
    }

    public static async Task ExampleCertificateVerificationByHealthCheck() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        // URL can omit the scheme, https:// will be used by default
        await healthCheck.VerifyWebsiteCertificate("evotec.pl");
        Helpers.ShowPropertiesTable("Certificate for evotec.pl ", healthCheck.CertificateAnalysis);
        Helpers.ShowPropertiesTable("Certificate for evotec.pl ", healthCheck.CertificateAnalysis.Certificate);
    }
}