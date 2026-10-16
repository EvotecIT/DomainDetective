using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>Observes a started, exclusively owned child process and both redirected streams through exit, including cancellation.</summary>
internal static class ProcessOutputCapture {
    internal static async Task<(string Output, string Error)> ReadUntilExitAsync(Process process, CancellationToken cancellationToken) {
        var exited = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        EventHandler handler = (_, _) => exited.TrySetResult(true);
        process.EnableRaisingEvents = true;
        process.Exited += handler;
        try {
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (process.HasExited) { exited.TrySetResult(true); }
            try {
                await exited.Task.WaitWithCancellation(cancellationToken).ConfigureAwait(false);
            } catch (OperationCanceledException) {
                if (!process.HasExited) {
                    try {
#if NET8_0_OR_GREATER
                        process.Kill(entireProcessTree: true);
#else
                        process.Kill();
#endif
                    } catch (InvalidOperationException) when (process.HasExited) { }
                }
                await exited.Task.ConfigureAwait(false);
                await Task.WhenAll(output, error).ConfigureAwait(false);
                throw;
            }
            await Task.WhenAll(output, error).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return (await output, await error);
        } finally { process.Exited -= handler; }
    }
}
