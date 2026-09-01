using DnsClientX;
using DomainDetective.Providers.Endpoint;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    private async Task EnrichEndpointObservationsAsync(
        IReadOnlyList<CertificateInventoryEntry> entries,
        CertificateInventoryCaptureOptions options,
        DateTimeOffset capturedAtUtc,
        List<string> warnings,
        CancellationToken cancellationToken) {
        string vantage = string.IsNullOrWhiteSpace(options.ProbeVantage)
            ? "default"
            : options.ProbeVantage.Trim();

        foreach (CertificateInventoryEntry entry in entries) {
            if (!entry.ObservedAtUtc.HasValue) {
                entry.ObservedAtUtc = capturedAtUtc;
            }
            if (string.IsNullOrWhiteSpace(entry.ProbeVantage)) {
                entry.ProbeVantage = vantage;
            }
        }

        if (!options.EnableEndpointAttribution || entries.Count == 0) {
            return;
        }

        var catalog = EndpointAttributionCatalog.CreateDefault();
        foreach (EndpointAttributionRule rule in options.EndpointAttributionRules) {
            catalog.AddOrReplace(rule);
        }

        AzureServiceTagCatalog? azureServiceTags = null;
        if (!string.IsNullOrWhiteSpace(options.AzureServiceTagsJsonPath)) {
            string serviceTagPath = options.AzureServiceTagsJsonPath!;
            try {
                azureServiceTags = AzureServiceTagCatalog.LoadFile(serviceTagPath);
            } catch (Exception ex) when (ex is IOException ||
                                         ex is UnauthorizedAccessException ||
                                         ex is ArgumentException ||
                                         ex is FormatException ||
                                         ex is JsonException) {
                warnings.Add($"Azure service-tag catalog could not be loaded from '{serviceTagPath}': {ex.Message}");
            }
        }

        var detector = new EndpointAttributionDetector(catalog);
        var resolver = new EndpointDnsEvidenceResolver {
            DnsConfiguration = new DnsConfiguration { DnsEndpoint = options.DnsEndpoint },
            QueryDnsOverride = EndpointDnsQueryOverride
        };
        var evidenceByHost = new ConcurrentDictionary<string, EndpointDnsEvidence>(StringComparer.OrdinalIgnoreCase);
        string[] hosts = entries
            .Select(GetObservationHost)
            .Where(host => host.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        int workerCount = Math.Min(hosts.Length, Math.Max(1, options.DnsEnrichmentParallelism));
        int nextHostIndex = -1;
        var workers = new Task[workerCount];
        for (int workerIndex = 0; workerIndex < workerCount; workerIndex++) {
            workers[workerIndex] = ResolveHostsAsync();
        }
        await Task.WhenAll(workers).ConfigureAwait(false);

        foreach (CertificateInventoryEntry entry in entries) {
            string host = GetObservationHost(entry);
            if (host.Length == 0 || !evidenceByHost.TryGetValue(host, out EndpointDnsEvidence? evidence)) {
                continue;
            }

            entry.DnsResolver = evidence.Resolver;
            entry.DnsObservedAtUtc = evidence.ObservedAtUtc;
            entry.CnameChain = evidence.CnameChain;
            entry.ResolvedAddresses = evidence.Addresses;
            entry.DnsObservationErrors = evidence.Errors;

            var addresses = new HashSet<string>(evidence.Addresses, StringComparer.OrdinalIgnoreCase);
            if (IPAddress.TryParse(entry.RemoteAddress, out IPAddress? remoteAddress) && remoteAddress != null) {
                addresses.Add(remoteAddress.ToString());
            }

            entry.Attribution = detector.Detect(
                new EndpointAttributionInput {
                    HostName = host,
                    Port = entry.Port,
                    Service = entry.Service,
                    CnameChain = evidence.CnameChain,
                    IpAddresses = addresses.ToArray(),
                    CertificateIssuer = entry.CertificateIssuer ?? string.Empty,
                    RedirectTargets = entry.RedirectTargets,
                    AzureServiceTags = azureServiceTags
                },
                DateTimeOffset.UtcNow);
        }

        async Task ResolveHostsAsync() {
            while (true) {
                cancellationToken.ThrowIfCancellationRequested();
                int hostIndex = Interlocked.Increment(ref nextHostIndex);
                if (hostIndex >= hosts.Length) {
                    return;
                }

                string host = hosts[hostIndex];
                EndpointDnsEvidence evidence = await resolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
                evidenceByHost[host] = evidence;
            }
        }
    }

    private static void ValidateEndpointAttributionCaptureOptions(CertificateInventoryCaptureOptions options) {
        if (!options.EnableEndpointAttribution) {
            return;
        }

        foreach (EndpointAttributionRule rule in options.EndpointAttributionRules) {
            EndpointAttributionCatalog.ValidateAndCompileRule(
                rule,
                nameof(CertificateInventoryCaptureOptions.EndpointAttributionRules));

            var unsupportedSignals = new List<string>(2);
            if (rule.ReverseDnsSuffixes.Count > 0) {
                unsupportedSignals.Add(nameof(EndpointAttributionRule.ReverseDnsSuffixes));
            }
            if (rule.AutonomousSystemNumbers.Count > 0) {
                unsupportedSignals.Add(nameof(EndpointAttributionRule.AutonomousSystemNumbers));
            }
            if (unsupportedSignals.Count > 0) {
                throw new NotSupportedException(
                    $"Certificate inventory capture cannot collect {string.Join(" or ", unsupportedSignals)} " +
                    $"for endpoint attribution rule '{rule.RuleId}'. Evaluate the rule with " +
                    $"{nameof(EndpointAttributionDetector)} directly and supply those observed signals explicitly.");
            }
        }
    }

    private static string GetObservationHost(CertificateInventoryEntry entry) {
        return (!string.IsNullOrWhiteSpace(entry.ResolvedHost) ? entry.ResolvedHost : entry.Host)
            ?.Trim()
            .TrimEnd('.')
            .ToLowerInvariant() ?? string.Empty;
    }
}
