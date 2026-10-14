using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Provides helper methods for working with tasks and cancellation tokens.
    /// </summary>
    internal static class CancellationExtensions {
        /// <summary>
        /// Waits for the task to complete while observing a cancellation token.
        /// </summary>
        public static async Task WaitWithCancellation(this Task task, CancellationToken token) {
#if NET8_0_OR_GREATER
            await task.WaitAsync(token).ConfigureAwait(false);
#else
            await WaitForCompletionAsync(task, token).ConfigureAwait(false);
#endif
        }

        /// <summary>
        /// Waits for the task to complete while observing a cancellation token and returns its result.
        /// </summary>
        public static async Task<T> WaitWithCancellation<T>(this Task<T> task, CancellationToken token) {
#if NET8_0_OR_GREATER
            return await task.WaitAsync(token).ConfigureAwait(false);
#else
            await WaitForCompletionAsync(task, token).ConfigureAwait(false);
            return await task.ConfigureAwait(false);
#endif
        }
        /// <summary>Portable wait with a registration whose lifetime ends on either completion path.</summary>
        internal static async Task WaitForCompletionAsync(Task task, CancellationToken token) {
            if (!token.CanBeCanceled || task.IsCompleted) {
                await task.ConfigureAwait(false);
                return;
            }
            var canceled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (token.Register(static state => ((TaskCompletionSource<bool>)state!).TrySetResult(true), canceled)) {
                if (await Task.WhenAny(task, canceled.Task).ConfigureAwait(false) != task) {
                    _ = task.ContinueWith(static completed => { _ = completed.Exception; }, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                    throw new OperationCanceledException(token);
                }
            }
            await task.ConfigureAwait(false);
        }
    }
}
