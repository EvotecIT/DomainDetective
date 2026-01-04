#if NET472
using System;
using System.Threading;
using System.Threading.Tasks;

namespace System.Threading
{
    /// <summary>
    /// Provides a simple timer that signals at a fixed period.
    /// </summary>
    internal sealed class PeriodicTimer : IDisposable
    {
        private readonly TimeSpan _period;
        private readonly CancellationTokenSource _cts = new();

        /// <summary>Creates the timer.</summary>
        /// <param name="period">The interval between ticks.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public PeriodicTimer(TimeSpan period)
        {
            if (period <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(period));
            }
            _period = period;
        }

        /// <summary>Waits for the next tick or cancellation.</summary>
        public async ValueTask<bool> WaitForNextTickAsync(CancellationToken cancellationToken = default)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
            try
            {
                await Task.Delay(_period, linked.Token).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }

        /// <summary>Stops the timer.</summary>
        public void Dispose()
        {
            _cts.Cancel();
        }
    }
}
#endif
