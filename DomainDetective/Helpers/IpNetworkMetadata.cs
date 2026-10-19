using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>RIPE observations shared by matching consumers without discarding per-address provenance.</summary>
internal static class IpNetworkMetadata {
    internal static Task<(string Prefix, int Asn)> PrefixAsync(HttpClient client, string ip, CancellationToken token) {
        if (!IPAddress.TryParse(ip, out var address)) { throw new ArgumentException("Invalid IP address.", nameof(ip)); }
        string normalized = address.ToString();
        return ShareAsync(("prefix", client, normalized), async requestToken => {
            using var response = await client.GetAsync(
                "https://stat.ripe.net/data/prefix-overview/data.json?resource=" + Uri.EscapeDataString(normalized), requestToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: requestToken).ConfigureAwait(false);
            var data = document.RootElement.GetProperty("data");
            var asns = data.GetProperty("asns");
            if (asns.GetArrayLength() == 0) { throw new InvalidOperationException("No ASN data was returned."); }
            return (data.GetProperty("resource").GetString() ?? string.Empty, asns[0].GetProperty("asn").GetInt32());
        }, token);
    }

    internal static Task<string?> RpkiStatusAsync(HttpClient client, string prefix, int asn, CancellationToken token) =>
        ShareAsync(("rpki", client, prefix, asn), async requestToken => {
            using var response = await client.GetAsync(
                $"https://stat.ripe.net/data/rpki-validation/data.json?prefix={Uri.EscapeDataString(prefix)}&resource=AS{asn}", requestToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: requestToken).ConfigureAwait(false);
            return document.RootElement.GetProperty("data").GetProperty("status").GetString();
        }, token);

    private static Task<T> ShareAsync<T>(object key, Func<CancellationToken, Task<T>> operation, CancellationToken caller) =>
        ScanObservations.Current?.ShareNetworkAsync(key, operation, caller) ?? operation(caller);
}
