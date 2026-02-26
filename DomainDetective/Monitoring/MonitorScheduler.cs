using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PeriodicTimer = System.Threading.PeriodicTimer;

namespace DomainDetective.Monitoring;

/// <summary>
/// Schedules periodic domain analyses and issues notifications on changes.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
/// <remarks>
/// The scheduler orchestrates several monitoring components and raises
/// notifications when their state changes between executions.
/// </remarks>
public class MonitorScheduler
{
    /// <summary>Domains to monitor.</summary>
    public List<string> Domains { get; } = new();

    /// <summary>Interval between runs.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(24);
    /// <summary>Maximum number of domains analyzed concurrently in one run.</summary>
    public int MaxDomainParallelism { get; set; } = 4;

    /// <summary>Notification sender.</summary>
    public INotificationSender? Notifier { get; set; }
    /// <summary>Override summary generation for testing.</summary>
    public Func<string, Task<DomainSummary>>? SummaryOverride { private get; set; }
    /// <summary>Override certificate check for testing.</summary>
    public Func<string, Task<CertificateMonitor.Entry>>? CertificateOverride { private get; set; }
    /// <summary>Override BGP prefix query for testing.</summary>
    public Func<string, CancellationToken, Task<Dictionary<string, int>>>? BgpOverride { private get; set; }

    private readonly ConcurrentDictionary<string, DomainSummary> _previous = new();
    private readonly ConcurrentDictionary<string, Dictionary<string, int>> _bgpPrevious = new();
    private readonly SemaphoreSlim _runLock = new(1, 1);
    private readonly SemaphoreSlim _notifyLock = new(1, 1);
    private PeriodicTimer? _timer;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;

    /// <summary>Starts the scheduler.</summary>
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

    /// <summary>Stops the scheduler.</summary>
    public void Stop()
    {
        _cts?.Cancel();
        _timer?.Dispose();
        _timer = null;
        _cts?.Dispose();
        _cts = null;
        _loopTask = null;
    }

    /// <summary>Runs all analyses once.</summary>
    public async Task RunAsync(CancellationToken ct = default)
    {
        if (!await _runLock.WaitAsync(0, ct))
        {
            return;
        }

        try
        {
            var domains = Domains
                .Where(domain => !string.IsNullOrWhiteSpace(domain))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (domains.Count == 0)
            {
                return;
            }

            var parallelism = Math.Max(1, MaxDomainParallelism);
            using var gate = new SemaphoreSlim(parallelism, parallelism);
            var tasks = new List<Task>(domains.Count);
            foreach (var domain in domains)
            {
                ct.ThrowIfCancellationRequested();
                await gate.WaitAsync(ct).ConfigureAwait(false);
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        await RunDomainAsync(domain, ct).ConfigureAwait(false);
                    }
                    finally
                    {
                        gate.Release();
                    }
                }, ct));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        finally
        {
            _runLock.Release();
        }
    }

    private async Task RunDomainAsync(string domain, CancellationToken ct)
    {
        var summary = SummaryOverride != null
            ? await SummaryOverride(domain).ConfigureAwait(false)
            : await BuildSummaryAsync(domain, ct).ConfigureAwait(false);

        if (_previous.TryGetValue(domain, out var prev))
        {
            if (!AreSummariesEqual(prev, summary))
            {
                await SendNotificationAsync($"Changes detected for {domain}", ct).ConfigureAwait(false);
            }
        }
        _previous[domain] = summary;

        var cert = CertificateOverride != null
            ? await CertificateOverride(domain).ConfigureAwait(false)
            : await CheckCertificateAsync(domain, ct).ConfigureAwait(false);

        if (cert.Expired)
        {
            await SendNotificationAsync($"Certificate expired for {domain}", ct).ConfigureAwait(false);
        }
        else if (!cert.Expired && (cert.ExpiryDate - DateTime.UtcNow).TotalDays <= 30)
        {
            await SendNotificationAsync($"Certificate for {domain} expires on {cert.ExpiryDate:yyyy-MM-dd}", ct).ConfigureAwait(false);
        }

        var prefixes = BgpOverride != null
            ? await BgpOverride(domain, ct).ConfigureAwait(false)
            : await BgpPrefixMonitor.QueryPrefixesAsync(domain, ct).ConfigureAwait(false);
        if (_bgpPrevious.TryGetValue(domain, out var prevPrefixes))
        {
            foreach (var kv in prefixes)
            {
                if (prevPrefixes.TryGetValue(kv.Key, out var prevAsn))
                {
                    if (prevAsn != kv.Value)
                    {
                        await SendNotificationAsync($"Prefix {kv.Key} for {domain} changed from AS{prevAsn} to AS{kv.Value}", ct).ConfigureAwait(false);
                    }
                }
                else
                {
                    await SendNotificationAsync($"Prefix {kv.Key} for {domain} announced by AS{kv.Value}", ct).ConfigureAwait(false);
                }
            }
        }
        _bgpPrevious[domain] = prefixes;
    }

    private async Task SendNotificationAsync(string message, CancellationToken ct)
    {
        if (Notifier == null)
        {
            return;
        }

        await _notifyLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (Notifier != null)
            {
                await Notifier.SendAsync(message, ct).ConfigureAwait(false);
            }
        }
        finally
        {
            _notifyLock.Release();
        }
    }

    private static bool AreSummariesEqual(DomainSummary a, DomainSummary b)
    {
        return a.HasSpfRecord == b.HasSpfRecord &&
            a.HasDmarcRecord == b.HasDmarcRecord &&
            a.HasMxRecord == b.HasMxRecord &&
            a.ExpiryDate == b.ExpiryDate;
    }

    private static async Task<DomainSummary> BuildSummaryAsync(string domain, CancellationToken ct)
    {
        var health = new DomainHealthCheck();
        await health.Verify(domain, cancellationToken: ct);
        return health.BuildSummary();
    }

    private static async Task<CertificateMonitor.Entry> CheckCertificateAsync(string domain, CancellationToken ct)
    {
        var monitor = new CertificateMonitor();
        await monitor.Analyze(new[] { $"https://{domain}" }, 443, new InternalLogger(), ct);
        return monitor.Results.First();
    }
}
