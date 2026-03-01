using DomainDetective.Helpers;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates reusable certificate inventory capture from domain portfolios.
/// </summary>
public static partial class Program {
    /// <summary>Captures one inventory snapshot for a reusable domain portfolio list.</summary>
    public static async Task ExampleCertificateInventoryCapture() {
        var domains = new[] {
            "evotec.xyz",
            "evotec.pl",
            "microsoft.com",
            "google.com",
            "eurofins.com",
            "abb.com"
        };

        var options = new CertificateInventoryCaptureOptions {
            CacheDirectory = @"C:\Temp\DomainDetective\cert-monitor",
            IncludeApexHttps = true,
            IncludeWwwHttps = true,
            IncludeMxHosts = true,
            IncludeSmtpStartTls = true,
            IncludeSubmissionStartTls = true,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = true,
            MaxParallelism = 24,
            DiscoveryParallelism = 32,
            MailTimeout = TimeSpan.FromSeconds(15)
        };
        options.AdditionalEndpoints.Add("https://api.microsoft.com:443");

        var capture = new CertificateInventoryCapture();
        var result = await capture.CaptureAsync(domains, options, new InternalLogger(false));

        Console.WriteLine($"CapturedAtUtc      : {result.CapturedAtUtc:O}");
        Console.WriteLine($"SnapshotPath       : {result.SnapshotPath}");
        Console.WriteLine($"Domains            : {result.DomainCount}");
        Console.WriteLine($"MX Hosts           : {result.MxHostCount}");
        Console.WriteLine($"HTTPS Endpoints    : {result.HttpsEndpointCount}");
        Console.WriteLine($"Mail Endpoints     : {result.MailEndpointCount}");
        Console.WriteLine($"Snapshot Entries   : {result.EntryCount}");
        Console.WriteLine($"Unique Endpoints   : {result.UniqueEndpointCount}");
        Console.WriteLine($"Valid / Expired    : {result.ValidCount} / {result.ExpiredCount}");
        Console.WriteLine($"Failed (no cert)   : {result.FailedCount}");
        Console.WriteLine();

        foreach (var warning in result.Warnings.Take(20)) {
            Console.WriteLine($"Warning: {warning}");
        }
        if (result.Warnings.Count > 20) {
            Console.WriteLine($"... {result.Warnings.Count - 20} more warning(s)");
        }

        var top = result.Snapshot.Entries
            .OrderBy(entry => entry.DaysToExpire)
            .ThenBy(entry => entry.Host, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .Select(entry => new {
                entry.Host,
                entry.Service,
                entry.Port,
                entry.CertificateIssuer,
                entry.NotAfterUtc,
                entry.DaysToExpire,
                entry.AuthenticationProfile,
                entry.AllowsClientAuthentication,
                entry.ChainComplete
            })
            .ToList();
        Helpers.ShowPropertiesTable("Top 10 soonest expirations", top);
    }
}
