using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>Maps indexed work with a fixed number of workers and ordered result slots.</summary>
internal static class BoundedAsyncWork {
    internal static async Task<T[]> MapAsync<T>(int count, int concurrency, Func<int, Task<T>> operation) {
        var results = new T[count];
        int next = -1;
        async Task Worker() {
            while (true) {
                int index = Interlocked.Increment(ref next);
                if (index >= count) return;
                results[index] = await operation(index).ConfigureAwait(false);
            }
        }
        await Task.WhenAll(Enumerable.Range(0, Math.Min(count, Math.Max(1, concurrency)))
            .Select(_ => Worker())).ConfigureAwait(false);
        return results;
    }
}
