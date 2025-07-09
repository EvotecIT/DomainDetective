using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring;

/// <summary>
/// Schedules periodic domain analyses and issues notifications on changes.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class MonitorScheduler
{
    /// <summary>Domains to monitor.</summary>
    public List<string> Domains { get; } = new();

    /// <summary>Interval between runs.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Notification sender.</summary>
    public INotificationSender? Notifier { get; set; }
    /// <summary>Override summary generation for testing.</summary>
    public Func<string, Task<DomainSummary>>? SummaryOverride { private get; set; }
    /// <summary>Override certificate check for testing.</summary>
    public Func<string, Task<CertificateMonitor.Entry>>? CertificateOverride { private get; set; }

    private readonly ConcurrentDictionary<string, DomainSummary> _previous = new();
    private readonly SemaphoreSlim _runLock = new(1, 1);
    private Timer? _timer;

    /// <summary>Starts the scheduler.</summary>
    public void Start()
    {
        _timer = new Timer(async _ => await RunAsync(), null, TimeSpan.Zero, Interval);
    }

    /// <summary>Stops the scheduler.</summary>
    public void Stop() => _timer?.Dispose();

    /// <summary>Runs all analyses once.</summary>
    public async Task RunAsync(CancellationToken ct = default)
    {
        if (!await _runLock.WaitAsync(0, ct))
        {
            return;
        }

        try
        {
            foreach (var domain in Domains)
            {
                ct.ThrowIfCancellationRequested();
                var summary = SummaryOverride != null
                    ? await SummaryOverride(domain)
                    : await BuildSummaryAsync(domain, ct);

                if (_previous.TryGetValue(domain, out var prev))
                {
                    if (!AreSummariesEqual(prev, summary) && Notifier != null)
                    {
                        await Notifier.SendAsync($"Changes detected for {domain}", ct);
                    }
                }
                _previous[domain] = summary;

                var cert = CertificateOverride != null
                    ? await CertificateOverride(domain)
                    : await CheckCertificateAsync(domain, ct);

                if (cert.Expired && Notifier != null)
                {
                    await Notifier.SendAsync($"Certificate expired for {domain}", ct);
                }
                else if (!cert.Expired && (cert.ExpiryDate - DateTime.UtcNow).TotalDays <= 30 && Notifier != null)
                {
                    await Notifier.SendAsync($"Certificate for {domain} expires on {cert.ExpiryDate:yyyy-MM-dd}", ct);
                }
            }
        }
        finally
        {
            _runLock.Release();
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
