using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>Runs a finite input with bounded worker allocation and ordered results.</summary>
internal static class BoundedAsync {
    internal static async Task<TResult[]> RunAsync<T, TResult>(IReadOnlyList<T> inputs,
        Func<T, Task<TResult>> action, int concurrency, CancellationToken cancellationToken) {
        var results = new TResult[inputs.Count];
        int next = -1;
        async Task WorkerAsync() {
            while (true) {
                cancellationToken.ThrowIfCancellationRequested();
                int index = Interlocked.Increment(ref next);
                if (index >= inputs.Count) { return; }
                results[index] = await action(inputs[index]).ConfigureAwait(false);
            }
        }
        var workers = new Task[Math.Min(Math.Max(1, concurrency), inputs.Count)];
        for (int i = 0; i < workers.Length; i++) { workers[i] = WorkerAsync(); }
        await Task.WhenAll(workers).ConfigureAwait(false);
        return results;
    }
}
