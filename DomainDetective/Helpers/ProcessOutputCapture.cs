using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>Captures a started, exclusively owned noninteractive child through exit, closing redirected input and draining both output streams, including cancellation.</summary>
internal static class ProcessOutputCapture {
    internal static Task<(string Output, string Error)> ReadUntilExitAsync(Process process, CancellationToken cancellationToken) =>
        ReadUntilExitAsync(process, cancellationToken, cancellationToken);

    /// <summary>Stops and drains the owned child when its wait budget expires, retaining available evidence unless the caller cancels.</summary>
    /// <param name="process">The started child owned exclusively by this probe.</param>
    /// <param name="waitToken">The probe deadline, linked to caller cancellation.</param>
    /// <param name="callerToken">Caller cancellation, which must propagate even when the probe deadline also expires.</param>
    internal static async Task<(string Output, string Error)> ReadUntilExitAsync(Process process, CancellationToken waitToken, CancellationToken callerToken) {
        var exited = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        EventHandler handler = (_, _) => exited.TrySetResult(true);
        process.EnableRaisingEvents = true;
        process.Exited += handler;
        try {
            if (process.StartInfo.RedirectStandardInput) { process.StandardInput.Close(); }
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (process.HasExited) { exited.TrySetResult(true); }
            try {
                await exited.Task.WaitWithCancellation(waitToken).ConfigureAwait(false);
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
            }
            await Task.WhenAll(output, error).ConfigureAwait(false);
            callerToken.ThrowIfCancellationRequested();
            return (await output, await error);
        } finally { process.Exited -= handler; }
    }
}
