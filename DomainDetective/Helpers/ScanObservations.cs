using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>
/// Owns semantically identical network observations for one verification lifetime.
/// Keys include the consumer policy and cancellation lifetime; independent calls
/// and subsequent scans never inherit an earlier run's results or failures.
/// </summary>
internal sealed class ScanObservations : IDisposable {
    private static readonly AsyncLocal<ScanObservations?> Slot = new();
    private readonly ScanObservations? _previous;
    private readonly ConcurrentDictionary<(Type, object), Lazy<object>> _operations = new();
    private readonly SharedAsyncOperations _networkOperations = new();
    private readonly ConcurrentDictionary<(Type, object), object> _completedNetwork = new();

    internal Task<T> ShareNetworkAsync<T>(object key, Func<CancellationToken, Task<T>> operation, CancellationToken caller) {
        caller.ThrowIfCancellationRequested();
        var typedKey = (typeof(T), key);
        if (_completedNetwork.TryGetValue(typedKey, out var completed)) { return Task.FromResult((T)completed); }
        return _networkOperations.RunAsync(key, async token => {
            if (_completedNetwork.TryGetValue(typedKey, out var prior)) { return (T)prior; }
            var result = await operation(token).ConfigureAwait(false);
            if (result != null) { _completedNetwork.TryAdd(typedKey, result); }
            return result;
        }, caller);
    }

    internal static ScanObservations? Current => Slot.Value;
    internal SemaphoreSlim DirectDnsAdmission { get; }

    internal ScanObservations(int directDnsParallelism = 32) {
        DirectDnsAdmission = new SemaphoreSlim(Math.Max(1, directDnsParallelism));
        _previous = Slot.Value;
        Slot.Value = this;
    }

    internal Task<T> ShareAsync<T>(object key, Func<Task<T>> operation) =>
        (Task<T>)_operations.GetOrAdd((typeof(T), key), _ =>
            new Lazy<object>(() => operation(), LazyThreadSafetyMode.ExecutionAndPublication)).Value;

    public void Dispose() => Slot.Value = _previous;
}
