using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Text.Json;
using DomainDetective.Helpers;
using DnsClientX;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class WhoisAnalysis : IHasAssessments {
    private void UpdatePrivacyFlag() {
        PrivacyProtected = false;
        foreach (var line in WhoisData.Split('\n')) {
            var trimmed = line.Trim();
            foreach (var indicator in _privacyIndicators) {
                if (trimmed.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0) {
                    PrivacyProtected = true;
                    return;
                }
            }
        }
    }

    /// <summary>
    /// Queries ARIN, RIPE and APNIC WHOIS servers for IP information.
    /// </summary>
    /// <param name="ipAddress">IP address to query.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>Tuple containing allocation and ASN when available.</returns>
    public async Task<(string? Allocation, string? Asn)> QueryIpWhois(string ipAddress, CancellationToken cancellationToken = default) {
        if (!IPAddress.TryParse(ipAddress, out _)) {
            throw new ArgumentException("Invalid IP address", nameof(ipAddress));
        }

        string? allocation = null;
        string? asn = null;

        List<string> servers;
        lock (_ipWhoisServersLock) {
            servers = new List<string>(IpWhoisServers);
        }

        foreach (var server in servers) {
            using var client = new TcpClient();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            try {
                var parts = server.Split(':');
                var host = parts[0];
                var port = 43;
                if (parts.Length > 1 && int.TryParse(parts[1], out var customPort)) {
                    port = customPort;
                }

                await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);

                using NetworkStream stream = client.GetStream();
                using (var writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { NewLine = "\r\n" }) {
                    await writer.WriteLineAsync(ipAddress).WaitWithCancellation(timeoutCts.Token);
                    await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                }

                await stream.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                using var ms = new MemoryStream();
                await stream.CopyToAsync(ms, 81920, timeoutCts.Token);
                var bytes = ms.ToArray();
                var response = Encoding.UTF8.GetString(bytes);
                if (response.Contains('\uFFFD')) {
                    response = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
                }

                foreach (var line in response.Split('\n')) {
                    var trimmed = line.Trim();
                    if (allocation == null &&
                        (trimmed.StartsWith("inetnum:", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("NetRange:", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("route:", StringComparison.OrdinalIgnoreCase))) {
                        var lineParts = trimmed.Split(':');
                        if (lineParts.Length > 1) {
                            allocation = lineParts[1].Trim();
                        }
                    } else if (asn == null &&
                        (trimmed.StartsWith("origin", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("OriginAS", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("aut-num:", StringComparison.OrdinalIgnoreCase))) {
                        var match = Regex.Match(trimmed, "AS\\d+", RegexOptions.IgnoreCase);
                        if (match.Success) {
                            asn = match.Value.ToUpperInvariant();
                        }
                    }

                    if (allocation != null && asn != null) {
                        break;
                    }
                }

                if (allocation != null && asn != null) {
                    break;
                }
            } catch (Exception ex) {
                _logger.WriteErrorCode(WhoisCodes.IpQueryFailed, "Error querying IP WHOIS server: {0}", ex.Message);
            }
        }

        return (allocation, asn);
    }

    /// <summary>
    /// Queries IANA RDAP for registrar information.
    /// </summary>
    public async Task QueryIana(string domain, CancellationToken cancellationToken = default) {
        string json;
        if (IanaQueryOverride != null) {
            json = await IanaQueryOverride(domain).ConfigureAwait(false);
        } else {
            var client = SharedHttpClient.Instance;
            try {
                using var response = await client.GetAsync($"https://rdap.iana.org/domain/{domain}", cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) {
                    // Gracefully ignore 404/NotFound and other non-success responses
                    return;
                }
                json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            } catch (HttpRequestException ex) {
                // Ignore IANA RDAP failures; WHOIS data may still be valid     
#if NET8_0_OR_GREATER
                if (ex.StatusCode.HasValue) {
                    return;
                }
#else
                _ = ex;
#endif
                return;
            }
        }

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("entities", out var entities)) {
            foreach (var ent in entities.EnumerateArray()) {
                if (ent.TryGetProperty("roles", out var roles)) {
                    foreach (var role in roles.EnumerateArray()) {
                        if (string.Equals(role.GetString(), "registrar", StringComparison.OrdinalIgnoreCase)) {
                            if (ent.TryGetProperty("handle", out var handle)) {
                                RegistrarId = handle.GetString();
                            }
                        }
                    }
                }
            }
        }

        if (string.IsNullOrEmpty(CreationDate) && doc.RootElement.TryGetProperty("events", out var events)) {
            foreach (var ev in events.EnumerateArray()) {
                if (ev.TryGetProperty("eventAction", out var action) &&
                    string.Equals(action.GetString(), "registration", StringComparison.OrdinalIgnoreCase) &&
                    ev.TryGetProperty("eventDate", out var date)) {
                    CreationDate = date.GetString();
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Saves the current WHOIS data snapshot to <see cref="SnapshotDirectory"/>.
    /// </summary>
    public void SaveSnapshot() {
        if (string.IsNullOrEmpty(SnapshotDirectory) || string.IsNullOrEmpty(DomainName) || string.IsNullOrEmpty(WhoisData)) {
            return;
        }
        Directory.CreateDirectory(SnapshotDirectory);
        var file = Path.Combine(SnapshotDirectory, $"{DomainName}_{DateTime.UtcNow:yyyyMMddHHmmss}.whois");
        File.WriteAllText(file, WhoisData, Encoding.UTF8);
    }

    /// <summary>
    /// Returns line level differences between the current WHOIS data and the last saved snapshot.
    /// </summary>
    public IEnumerable<string> GetWhoisChanges() {
        if (string.IsNullOrEmpty(SnapshotDirectory) || string.IsNullOrEmpty(DomainName)) {
            return Array.Empty<string>();
        }
        var files = Directory.GetFiles(SnapshotDirectory, $"{DomainName}_*.whois");
        if (files.Length == 0) {
            return Array.Empty<string>();
        }
        var previousFile = files.OrderByDescending(f => f).First();
        var previousData = File.ReadAllText(previousFile);
        var previousLines = previousData.Split('\n');
        var currentLines = WhoisData.Split('\n');
        var changes = new List<string>();
        var max = Math.Max(previousLines.Length, currentLines.Length);
        for (var i = 0; i < max; i++) {
            var prev = i < previousLines.Length ? previousLines[i] : string.Empty;
            var curr = i < currentLines.Length ? currentLines[i] : string.Empty;
            if (!string.Equals(prev, curr, StringComparison.Ordinal)) {
                changes.Add("- " + prev);
                changes.Add("+ " + curr);
            }
        }
        return changes;
    }

}
