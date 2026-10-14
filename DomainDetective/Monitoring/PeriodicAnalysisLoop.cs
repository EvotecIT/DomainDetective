using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring;

/// <summary>Serializes periodic run transitions and owns the captured timer and cancellation generation.</summary>
internal sealed class PeriodicAnalysisLoop {
    private readonly SemaphoreSlim _transitions = new(1, 1);
    private CancellationTokenSource? _cancellation;
    private Task? _loop;
    private PeriodicTimer? _timer;

    internal bool IsRunning => Volatile.Read(ref _cancellation) != null;

    internal void Start(TimeSpan interval, Func<CancellationToken, Task> analyze, Action? prepare = null) {
        _transitions.Wait();
        try {
            StopCurrentAsync().GetAwaiter().GetResult();
            prepare?.Invoke();
            var timer = new PeriodicTimer(interval);
            var cancellation = new CancellationTokenSource();
            _cancellation = cancellation;
            _timer = timer;
            _loop = Task.Run(async () => {
                try {
                    await analyze(cancellation.Token).ConfigureAwait(false);
                    while (await timer.WaitForNextTickAsync(cancellation.Token).ConfigureAwait(false)) {
                        await analyze(cancellation.Token).ConfigureAwait(false);
                    }
                } catch (OperationCanceledException) when (cancellation.IsCancellationRequested) {
                    // Stop ends only this captured generation.
                }
            });
        } finally {
            _transitions.Release();
        }
    }

    internal async Task StopAsync() {
        await _transitions.WaitAsync().ConfigureAwait(false);
        try {
            await StopCurrentAsync().ConfigureAwait(false);
        } finally {
            _transitions.Release();
        }
    }

    private async Task StopCurrentAsync() {
        if (_cancellation == null) {
            return;
        }
        var cancellation = _cancellation;
        Exception? cancellationFailure = null;
        try {
            try { cancellation.Cancel(); } catch (Exception error) { cancellationFailure = error; }
            if (_loop != null) {
                try {
                    await _loop.ConfigureAwait(false);
                } catch (OperationCanceledException) {
                    // Stop also drains a generation whose analysis had already been canceled.
                }
            }
            if (cancellationFailure != null) {
                throw new AggregateException("A cancellation callback failed.", cancellationFailure);
            }
        } finally {
            _timer?.Dispose();
            cancellation.Dispose();
            _timer = null;
            _cancellation = null;
            _loop = null;
        }
    }
}
