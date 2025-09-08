using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring;

/// <summary>
/// Minimal scheduler for uptime probes over HTTP(S) with optional notifications and JSON snapshots.
/// </summary>
public sealed class UptimeMonitor : IDisposable
{
    private readonly List<string> _targets = new();
    private Timer? _timer;
    private readonly TimeSpan _interval;
    private readonly string? _snapshotDirectory;
    public INotificationSender? Notifier { get; set; }
    public int MaxStatusCodeOk { get; set; } = 399;
    public int MinStatusCodeOk { get; set; } = 200;
    public int SlowTtfbMsThreshold { get; set; } = 2000;
    public Func<DomainDetective.UptimeProbeAnalysis, CancellationToken, Task>? OnDown { get; set; }
    public Func<DomainDetective.UptimeProbeAnalysis, CancellationToken, Task>? OnSlow { get; set; }
    public Func<DomainDetective.UptimeProbeAnalysis, CancellationToken, Task>? OnUp { get; set; }
    public Func<DomainDetective.UptimeProbeAnalysis, string, CancellationToken, Task>? OnAny { get; set; }

    public UptimeMonitor(IEnumerable<string> urls, TimeSpan interval, string? snapshotDirectory = null)
    {
        if (urls != null) _targets.AddRange(urls);
        _interval = interval <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : interval;
        _snapshotDirectory = snapshotDirectory;
        if (!string.IsNullOrWhiteSpace(_snapshotDirectory)) Directory.CreateDirectory(_snapshotDirectory);
    }

    public void Start()
    {
        _timer = new Timer(async _ => await TickAsync().ConfigureAwait(false), null, TimeSpan.Zero, _interval);
    }

    public void Stop()
    {
        _timer?.Change(Timeout.Infinite, Timeout.Infinite);
        _timer?.Dispose();
        _timer = null;
    }

    private async Task TickAsync()
    {
        var logger = new InternalLogger();
        foreach (var url in _targets)
        {
            try
            {
                var probe = new UptimeProbeAnalysis();
                await probe.ProbeAsync(url, logger).ConfigureAwait(false);

                if (!string.IsNullOrWhiteSpace(_snapshotDirectory))
                {
                    var name = Sanitize(url) + "_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss") + ".json";
                    var path = Path.Combine(_snapshotDirectory!, name);
                    await probe.SaveSnapshotAsync(path).ConfigureAwait(false);
                }

                if (Notifier != null || OnDown != null || OnSlow != null || OnUp != null)
                {
                    if (!probe.Success || probe.StatusCode < MinStatusCodeOk || probe.StatusCode > MaxStatusCodeOk)
                    {
                        if (Notifier != null)
                            await Notifier.SendAsync($"Uptime DOWN: {url} status={probe.StatusCode} ttfb={probe.TtfbMilliseconds}ms").ConfigureAwait(false);
                        if (OnDown != null)
                            try { await OnDown(probe, CancellationToken.None).ConfigureAwait(false); } catch { }
                        if (OnAny != null)
                            try { await OnAny(probe, "Down", CancellationToken.None).ConfigureAwait(false); } catch { }
                    }
                    else if (probe.TtfbMilliseconds >= SlowTtfbMsThreshold)
                    {
                        if (Notifier != null)
                            await Notifier.SendAsync($"Uptime SLOW: {url} ttfb={probe.TtfbMilliseconds}ms").ConfigureAwait(false);
                        if (OnSlow != null)
                            try { await OnSlow(probe, CancellationToken.None).ConfigureAwait(false); } catch { }
                        if (OnAny != null)
                            try { await OnAny(probe, "Slow", CancellationToken.None).ConfigureAwait(false); } catch { }
                    }
                    else if (OnUp != null)
                    {
                        try { await OnUp(probe, CancellationToken.None).ConfigureAwait(false); } catch { }
                        if (OnAny != null)
                            try { await OnAny(probe, "Up", CancellationToken.None).ConfigureAwait(false); } catch { }
                    }
                }
            }
            catch { /* best-effort scheduler tick */ }
        }
    }

    private static string Sanitize(string s)
    {
        foreach (var ch in Path.GetInvalidFileNameChars()) s = s.Replace(ch, '_');
        return s.Replace(":", "_").Replace("/", "_");
    }

    public void Dispose()
    {
        Stop();
    }
}
