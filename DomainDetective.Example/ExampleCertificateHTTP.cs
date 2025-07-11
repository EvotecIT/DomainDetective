using DomainDetective;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates certificate analysis functions.
/// </summary>
public static partial class Program {

    /// <summary>Checks a single website certificate.</summary>
    public static async Task ExampleCertificateVerification() {
        var analysis = await CertificateAnalysis.CheckWebsiteCertificate("https://google.com");
        Helpers.ShowPropertiesTable("Certificate for google.com", analysis);
        Helpers.ShowPropertiesTable("Certificate for google.com", analysis.Certificate);
    }

    /// <summary>Checks a website certificate via <see cref="DomainHealthCheck"/>.</summary>
    public static async Task ExampleCertificateVerificationByHealthCheck() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        // URL can omit the scheme, https:// will be used by default
        await healthCheck.VerifyWebsiteCertificate("evotec.pl");
        Helpers.ShowPropertiesTable("Certificate for evotec.pl ", healthCheck.CertificateAnalysis);
        Helpers.ShowPropertiesTable("Certificate for evotec.pl ", healthCheck.CertificateAnalysis.Certificate);
    }

    /// <summary>Shows expiration details for a certificate.</summary>
    public static async Task ExampleCertificateExpiration() {
        var analysis = await CertificateAnalysis.CheckWebsiteCertificate("https://google.com");
        Console.WriteLine($"Expired       : {analysis.IsExpired}");
        Console.WriteLine($"Days left     : {analysis.DaysToExpire}");
        Console.WriteLine($"Days valid    : {analysis.DaysValid}");
    }
}