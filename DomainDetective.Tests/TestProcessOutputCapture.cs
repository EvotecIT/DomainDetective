using System.Diagnostics;

namespace DomainDetective.Tests;

public class TestProcessOutputCapture {
    private static readonly TimeSpan FixtureGuard = TimeSpan.FromSeconds(30);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProbeDeadlineRetainsDrainedEvidenceUnlessCallerCanceled(bool callerCanceled) {
        string folder = Path.Combine(Path.GetTempPath(), "dd-process-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string ready = Path.Combine(folder, "ready");
        // Native shell built-ins write both streams and the marker, then wait for stdin EOF.
        // Process startup is setup; the probe deadline is canceled only after readiness.
        using var process = Start(
            "echo OCSP Response Status: successful & echo diagnostic 1>&2 & echo ready > ready & set /p answer=",
            "printf 'OCSP Response Status: successful'; printf diagnostic >&2; printf ready > ready; read answer",
            folder);
        try {
            using var guard = new CancellationTokenSource(FixtureGuard);
            while (!File.Exists(ready)) {
                if (process.HasExited) {
                    throw new InvalidOperationException($"Process fixture exited before readiness ({process.ExitCode}): " +
                        await process.StandardError.ReadToEndAsync());
                }
                await Task.Delay(20, guard.Token);
            }
            using var deadline = new CancellationTokenSource();
            using var caller = new CancellationTokenSource();
            deadline.Cancel();
            if (callerCanceled) { caller.Cancel(); }
            if (callerCanceled) {
                var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, deadline.Token, caller.Token));
                Assert.Equal(caller.Token, exception.CancellationToken);
            } else {
                var captured = await Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, deadline.Token, caller.Token);
                Assert.Equal("OCSP Response Status: successful", captured.Output.Trim());
                Assert.Equal("diagnostic", captured.Error.Trim());
            }
            Assert.True(process.HasExited);
        } finally {
            StopOwnedProcess(process);
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task NonInteractiveCaptureClosesStdinBeforeWaitingForExit() {
        using var process = Start("set /p answer= & echo received-eof", "read answer; printf received-eof");
        using var guard = new CancellationTokenSource(FixtureGuard);
        var captured = await Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, guard.Token);
        Assert.Equal("received-eof", captured.Output.Trim());
        Assert.True(process.HasExited);
    }

    [Fact]
    public async Task CapturesBothStreamsThroughExit() {
        using var process = Start("echo stdout & echo stderr 1>&2", "printf stdout; printf stderr >&2");
        using var guard = new CancellationTokenSource(FixtureGuard);
        var captured = await Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, guard.Token);
        Assert.True(process.HasExited);
        Assert.Equal("stdout", captured.Output.Trim());
        Assert.Equal("stderr", captured.Error.Trim());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationStopsOwnedChildAndDrainsItsStreams(bool callerCanceled) {
        bool windows = Path.DirectorySeparatorChar == '\\';
        using var process = Process.Start(new ProcessStartInfo {
            FileName = windows ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ping.exe") : "/bin/sleep",
            Arguments = windows ? "-t 127.0.0.1" : "300",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
        using var cancellation = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(FixtureGuard);
        Assert.False(process.HasExited);
        cancellation.Cancel();
        var capture = callerCanceled
            ? Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, cancellation.Token)
            : Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, cancellation.Token, CancellationToken.None);
        try {
            if (callerCanceled) {
                var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => capture.WaitWithCancellation(guard.Token));
                Assert.Equal(cancellation.Token, exception.CancellationToken);
            } else {
                await capture.WaitWithCancellation(guard.Token);
            }
            Assert.True(process.HasExited);
        } finally {
            StopOwnedProcess(process);
            try { await capture; }
            catch (OperationCanceledException) when (callerCanceled) { }
        }
    }

    private static void StopOwnedProcess(Process process) {
        if (!process.HasExited) {
            try {
#if NET8_0_OR_GREATER
                process.Kill(entireProcessTree: true);
#else
                process.Kill();
#endif
            } catch (InvalidOperationException) when (process.HasExited) { }
            process.WaitForExit();
        }
    }

    private static Process Start(string windowsCommand, string posixCommand, string? workingDirectory = null) {
        bool windows = Path.DirectorySeparatorChar == '\\';
        return Process.Start(new ProcessStartInfo {
            FileName = windows ? Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe" : "/bin/sh",
            Arguments = windows ? $"/d /q /s /c \"{windowsCommand}\"" : $"-c \"{posixCommand}\"",
            WorkingDirectory = workingDirectory ?? string.Empty,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
    }
}
