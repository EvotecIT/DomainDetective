using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static Task ExampleManageDnsbl() {
        var analysis = new DNSBLAnalysis();

        // add a provider
        analysis.AddDNSBL("dnsbl.example.com", comment: "custom");

        // remove a provider
        analysis.RemoveDNSBL("dnsbl.example.com");

        // clear all configured providers
        analysis.ClearDNSBL();

        // load providers from configuration
        analysis.LoadDnsblConfig("DnsblProviders.sample.json", overwriteExisting: true);

        return Task.CompletedTask;
    }
}
