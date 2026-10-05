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
    private static readonly TimeSpan MaxTaskDelay = TimeSpan.FromMilliseconds(int.MaxValue - 1);
    private readonly List<string> _targets = new();
    private readonly object _lifecycleSync = new();
    private readonly SemaphoreSlim _tickLock = new(1, 1);
    private CancellationTokenSource? _runCancellation;
    private Task? _loopTask;
    private Task _stoppingTask = Task.CompletedTask;
    private bool _disposed;
    private readonly TimeSpan _interval;
    private readonly string? _snapshotDirectory;
    /// <summary>Gets or sets the notifier value.</summary>
    public INotificationSender? Notifier { get; set; }
    /// <summary>Gets or sets the max status code ok value.</summary>
    public int MaxStatusCodeOk { get; set; } = 399;
    /// <summary>Gets or sets the min status code ok value.</summary>
    public int MinStatusCodeOk { get; set; } = 200;
    /// <summary>Gets or sets the slow ttfb ms threshold value.</summary>
    public int SlowTtfbMsThreshold { get; set; } = 2000;
    /// <summary>Gets or sets the on down value.</summary>
    public Func<DomainDetective.UptimeProbeAnalysis, CancellationToken, Task>? OnDown { get; set; }
    /// <summary>Gets or sets the on slow value.</summary>
    public Func<DomainDetective.UptimeProbeAnalysis, CancellationToken, Task>? OnSlow { get; set; }
    /// <summary>Gets or sets the on up value.</summary>
    public Func<DomainDetective.UptimeProbeAnalysis, CancellationToken, Task>? OnUp { get; set; }
    /// <summary>Gets or sets the on any value.</summary>
    public Func<DomainDetective.UptimeProbeAnalysis, string, CancellationToken, Task>? OnAny { get; set; }

    /// <summary>Initializes a new instance of the UptimeMonitor class.</summary>
    public UptimeMonitor(IEnumerable<string> urls, TimeSpan interval, string? snapshotDirectory = null)
    {
        if (urls != null) _targets.AddRange(urls);
        _interval = interval <= TimeSpan.Zero
            ? TimeSpan.FromMinutes(1)
            : interval < TimeSpan.FromMilliseconds(1) ? TimeSpan.FromMilliseconds(1) : interval;
        _snapshotDirectory = snapshotDirectory;
        if (!string.IsNullOrWhiteSpace(_snapshotDirectory)) Directory.CreateDirectory(_snapshotDirectory);
    }

    /// <summary>Executes the start operation.</summary>
    public void Start()
    {
        lock (_lifecycleSync)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(UptimeMonitor));
            }

            if (_runCancellation != null)
            {
                return;
            }

            var cancellation = new CancellationTokenSource();
            _runCancellation = cancellation;
            _loopTask = Task.Run(() => RunLoopAsync(cancellation.Token));
        }
    }

    /// <summary>Requests cancellation of the current run without waiting for callbacks to finish.</summary>
    public void Stop()
    {
        _ = StopCore();
    }

    /// <summary>
    /// Cancels the current run and waits for its probe and callbacks to finish.
    /// A callback in that run should call <see cref="Stop"/> to request cancellation without
    /// waiting for itself.
    /// </summary>
    public Task StopAsync()
    {
        return StopCore();
    }

    private Task StopCore()
    {
        CancellationTokenSource? cancellation;
        TaskCompletionSource<bool> cancellationDelivered;
        Task stoppingTask;
        lock (_lifecycleSync)
        {
            cancellation = _runCancellation;
            if (cancellation == null)
            {
                return _stoppingTask;
            }

            var loopTask = _loopTask!;
            _runCancellation = null;
            _loopTask = null;
            Task previous = _stoppingTask.Status == TaskStatus.RanToCompletion
                ? Task.CompletedTask
                : _stoppingTask;
            cancellationDelivered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _stoppingTask = DrainAsync(previous, loopTask, cancellationDelivered.Task, cancellation);
            stoppingTask = _stoppingTask;
        }

        try
        {
            cancellation.Cancel();
        }
        finally
        {
            cancellationDelivered.TrySetResult(true);
        }
        return stoppingTask;
    }

    private static async Task DrainAsync(Task previous, Task current, Task cancellationDelivered, CancellationTokenSource cancellation)
    {
        try
        {
            await cancellationDelivered.ConfigureAwait(false);
            await Task.WhenAll(previous, current).ConfigureAwait(false);
        }
        finally
        {
            cancellation.Dispose();
        }
    }

    private async Task RunLoopAsync(CancellationToken cancellation)
    {
        try
        {
            while (true)
            {
                cancellation.ThrowIfCancellationRequested();
                await _tickLock.WaitAsync(cancellation).ConfigureAwait(false);
                try
                {
                    await TickAsync(cancellation).ConfigureAwait(false);
                }
                finally
                {
                    _tickLock.Release();
                }

                await WaitIntervalAsync(_interval, cancellation).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // Stopping the monitor ends the current generation.
        }
    }

    private static async Task WaitIntervalAsync(TimeSpan interval, CancellationToken cancellation)
    {
        TimeSpan remaining = interval;
        while (remaining > TimeSpan.Zero)
        {
            TimeSpan delay = remaining > MaxTaskDelay ? MaxTaskDelay : remaining;
            await Task.Delay(delay, cancellation).ConfigureAwait(false);
            remaining -= delay;
        }
    }

    private async Task TickAsync(CancellationToken cancellation)
    {
        var logger = new InternalLogger();
        foreach (var url in _targets)
        {
            try
            {
                cancellation.ThrowIfCancellationRequested();
                var probe = new UptimeProbeAnalysis();
                await probe.ProbeAsync(url, logger, cancellation).ConfigureAwait(false);

                if (!string.IsNullOrWhiteSpace(_snapshotDirectory))
                {
                    var name = Sanitize(url) + "_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss") + ".json";
                    var path = Path.Combine(_snapshotDirectory!, name);
                    await probe.SaveSnapshotAsync(path, cancellation).ConfigureAwait(false);
                }

                if (Notifier != null || OnDown != null || OnSlow != null || OnUp != null || OnAny != null)
                {
                    string severity;
                    if (!probe.Success || probe.StatusCode < MinStatusCodeOk || probe.StatusCode > MaxStatusCodeOk)
                    {
                        severity = "Down";
                        if (Notifier is { } downNotifier) {
                            try {
                                await downNotifier.SendAsync($"Uptime DOWN: {url} status={probe.StatusCode} ttfb={probe.TtfbMilliseconds}ms", cancellation).ConfigureAwait(false);
                            } catch { }
                        }
                        cancellation.ThrowIfCancellationRequested();
                        if (OnDown is { } onDown)
                            try { await onDown(probe, cancellation).ConfigureAwait(false); } catch { }
                    }
                    else if (probe.TtfbMilliseconds >= SlowTtfbMsThreshold)
                    {
                        severity = "Slow";
                        if (Notifier is { } slowNotifier) {
                            try {
                                await slowNotifier.SendAsync($"Uptime SLOW: {url} ttfb={probe.TtfbMilliseconds}ms", cancellation).ConfigureAwait(false);
                            } catch { }
                        }
                        cancellation.ThrowIfCancellationRequested();
                        if (OnSlow is { } onSlow)
                            try { await onSlow(probe, cancellation).ConfigureAwait(false); } catch { }
                    }
                    else
                    {
                        severity = "Up";
                        if (OnUp is { } onUp)
                            try { await onUp(probe, cancellation).ConfigureAwait(false); } catch { }
                    }
                    cancellation.ThrowIfCancellationRequested();
                    if (OnAny is { } onAny)
                        try { await onAny(probe, severity, cancellation).ConfigureAwait(false); } catch { }
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                throw;
            }
            catch { /* best-effort scheduler tick */ }
        }
    }

    private static string Sanitize(string s)
    {
        foreach (var ch in Path.GetInvalidFileNameChars()) s = s.Replace(ch, '_');
        return s.Replace(":", "_").Replace("/", "_");
    }

    /// <summary>Executes the dispose operation.</summary>
    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            _disposed = true;
        }
        Stop();
    }
}
