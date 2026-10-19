using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>
/// Coalesces identical owned operations with independent waiter cancellation.
/// The final waiter cancels and drains unfinished work before returning.
/// Completed-result retention belongs to the typed observation owner.
/// </summary>
internal sealed class SharedAsyncOperations {
    private sealed class Entry {
        internal readonly CancellationTokenSource Lifetime = new();
        internal readonly Lazy<Task<object?>> Work;
        internal int Waiters;
        internal Entry(Func<CancellationToken, Task<object?>> work) {
            Work = new Lazy<Task<object?>>(() => work(Lifetime.Token), LazyThreadSafetyMode.ExecutionAndPublication);
        }
    }

    private readonly object _gate = new();
    private readonly Dictionary<(Type, object), Entry> _entries = new();

    internal async Task<T> RunAsync<T>(object identity, Func<CancellationToken, Task<T>> operation, CancellationToken caller) {
        caller.ThrowIfCancellationRequested();
        var key = (typeof(T), identity);
        Entry entry;
        lock (_gate) {
            if (!_entries.TryGetValue(key, out entry!)) {
                entry = new Entry(async token => await operation(token).ConfigureAwait(false));
                _entries.Add(key, entry);
            }
            entry.Waiters++;
        }
        var work = entry.Work.Value;
        try { return (T)(await work.WaitWithCancellation(caller).ConfigureAwait(false))!; }
        finally {
            bool last;
            lock (_gate) {
                last = --entry.Waiters == 0;
                if (last) { _entries.Remove(key); }
            }
            if (last) {
                try {
                    if (!work.IsCompleted) {
                        try { entry.Lifetime.Cancel(); } catch (AggregateException) { }
                    }
                    try { await work.ConfigureAwait(false); } catch { }
                } finally { entry.Lifetime.Dispose(); }
            }
        }
    }
}
