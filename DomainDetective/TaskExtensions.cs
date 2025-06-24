using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    internal static class TaskExtensions {
        public static async Task WaitWithCancellation(this Task task, CancellationToken token) {
#if NET6_0_OR_GREATER
            await task.WaitAsync(token).ConfigureAwait(false);
#else
            var delayTask = Task.Delay(Timeout.Infinite, token);
            if (await Task.WhenAny(task, delayTask).ConfigureAwait(false) != task) {
                throw new OperationCanceledException(token);
            }
            await task.ConfigureAwait(false);
#endif
        }

        public static async Task<T> WaitWithCancellation<T>(this Task<T> task, CancellationToken token) {
#if NET6_0_OR_GREATER
            return await task.WaitAsync(token).ConfigureAwait(false);
#else
            var delayTask = Task.Delay(Timeout.Infinite, token);
            if (await Task.WhenAny(task, delayTask).ConfigureAwait(false) != task) {
                throw new OperationCanceledException(token);
            }
            return await task.ConfigureAwait(false);
#endif
        }
    }
}
