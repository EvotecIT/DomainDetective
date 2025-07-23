using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PeriodicTimer = System.Threading.PeriodicTimer;

namespace DomainDetective.Monitoring;

/// <summary>
/// Monitors BGP origin ASNs for domain IP prefixes.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
/// <remarks>
/// Notifications are generated when the announcing ASN for a prefix changes,
/// helping detect possible hijacks or routing errors.
/// </remarks>
public class BgpPrefixMonitor
{
    /// <summary>Domain to monitor.</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Interval between checks.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Notification sender.</summary>
    public INotificationSender? Notifier { get; set; }

    /// <summary>Configure a webhook notification.</summary>
    public void UseWebhook(string url)
    {
        Notifier = NotificationSenderFactory.CreateWebhook(url);
    }

    /// <summary>Configure an email notification.</summary>
    public void UseEmail(string smtpHost, int port, bool useSsl, string from, string to, string? username = null, string? password = null)
    {
        Notifier = NotificationSenderFactory.CreateEmail(smtpHost, port, useSsl, from, to, username, password);
    }

    /// <summary>Configure a custom notification handler.</summary>
    public void UseCustom(Func<string, CancellationToken, Task> handler)
    {
        Notifier = NotificationSenderFactory.CreateCustom(handler);
    }

    /// <summary>Override prefix query for testing.</summary>
    public Func<CancellationToken, Task<Dictionary<string, int>>>? QueryOverride { private get; set; }

    private readonly Dictionary<string, int> _previous = new(StringComparer.Ordinal);
    private PeriodicTimer? _timer;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;

    /// <summary>Starts the monitor.</summary>
    public void Start()
    {
        Stop();
        _cts = new CancellationTokenSource();
        _timer = new PeriodicTimer(Interval);
        _loopTask = Task.Run(async () =>
        {
            await RunAsync().ConfigureAwait(false);
            while (_timer != null && await _timer.WaitForNextTickAsync(_cts.Token).ConfigureAwait(false))
            {
                await RunAsync().ConfigureAwait(false);
            }
        });
    }

    /// <summary>Stops the monitor.</summary>
    public void Stop()
    {
        _cts?.Cancel();
        _timer?.Dispose();
        _timer = null;
        _cts?.Dispose();
        _cts = null;
        _loopTask = null;
    }

    /// <summary>Runs a single check.</summary>
    public async Task RunAsync(CancellationToken ct = default)
    {
        var current = QueryOverride != null
            ? await QueryOverride(ct).ConfigureAwait(false)
            : await QueryPrefixesAsync(Domain, ct).ConfigureAwait(false);
        foreach (var kvp in current)
        {
            if (_previous.TryGetValue(kvp.Key, out var prevAsn))
            {
                if (prevAsn != kvp.Value && Notifier != null)
                {
                    await Notifier.SendAsync($"Prefix {kvp.Key} for {Domain} changed from AS{prevAsn} to AS{kvp.Value}", ct).ConfigureAwait(false);
                }
            }
            else if (Notifier != null)
            {
                await Notifier.SendAsync($"Prefix {kvp.Key} for {Domain} announced by AS{kvp.Value}", ct).ConfigureAwait(false);
            }
            _previous[kvp.Key] = kvp.Value;
        }
    }

    internal static async Task<Dictionary<string, int>> QueryPrefixesAsync(string domain, CancellationToken ct)
    {
        var config = new DnsConfiguration();
        var a = await config.QueryDNS(domain, DnsRecordType.A, cancellationToken: ct).ConfigureAwait(false);
        var aaaa = await config.QueryDNS(domain, DnsRecordType.AAAA, cancellationToken: ct).ConfigureAwait(false);
        var ips = a.Concat(aaaa).Select(r => r.Data).Distinct(StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var ip in ips)
        {
            var url = $"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = await SharedHttpClient.Instance.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                continue;
            }
#if NET6_0_OR_GREATER
            using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#else
            using var stream = await response.Content.ReadAsStreamAsync().WaitWithCancellation(ct).ConfigureAwait(false);
#endif
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            var data = doc.RootElement.GetProperty("data");
            var prefix = data.GetProperty("resource").GetString() ?? ip;
            var asns = data.GetProperty("asns");
            if (asns.GetArrayLength() == 0)
            {
                continue;
            }
            var asn = asns[0].GetProperty("asn").GetInt32();
            result[prefix] = asn;
        }
        return result;
    }
}
