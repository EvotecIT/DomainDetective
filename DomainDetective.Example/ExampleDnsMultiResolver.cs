using System;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective.Example
{
    public static class ExampleDnsMultiResolver
    {
        public static async Task Run()
        {
            var logger = new DomainDetective.InternalLogger(isVerbose: true);
            var hc = new DomainDetective.DomainHealthCheck(DnsEndpoint.System, logger)
            {
                // Prefer local validation toggle off; rely on upstream AD
                DnsSecValidateLocally = false
            };

            // Multi-resolver: try Cloudflare wire-format, then Google (FirstSuccess)
            hc.DnsEndpoints.Add(DnsEndpoint.CloudflareWireFormat);
            hc.DnsEndpoints.Add(DnsEndpoint.Google);
            hc.MultiResolverStrategy = DomainDetective.MultiResolverStrategy.FirstSuccess;

            await hc.Verify("example.com", new[]
            {
                DomainDetective.HealthCheckType.SPF,
                DomainDetective.HealthCheckType.DNSSEC
            });

            Console.WriteLine($"SPF present: {hc.SpfAnalysis.SpfRecordExists}");
            Console.WriteLine($"DS count: {hc.DnsSecAnalysis.DsRecords?.Count ?? 0}");
        }
    }
}

