using System.Diagnostics;

namespace DomainDetective.Tests;

public class TestProcessOutputCapture {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProbeDeadlineRetainsDrainedEvidenceUnlessCallerCanceled(bool callerCanceled) {
        string folder = Path.Combine(Path.GetTempPath(), "dd-process-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string ready = Path.Combine(folder, "ready");
        string script = Path.Combine(folder, "probe.ps1");
        bool windows = Path.DirectorySeparatorChar == '\\';
        File.WriteAllText(script, "[Console]::Out.Write('OCSP Response Status: successful'); [Console]::Out.Flush(); " +
            "[Console]::Error.Write('diagnostic'); [Console]::Error.Flush(); " +
            "[IO.File]::WriteAllText($args[0], 'ready'); Start-Sleep -Seconds 20");
        using var process = Process.Start(new ProcessStartInfo {
            FileName = windows ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh",
            Arguments = windows ? $"-NoProfile -NonInteractive -File \"{script}\" \"{ready}\"" :
                $"-c \"printf 'OCSP Response Status: successful'; printf diagnostic >&2; printf ready > '{ready}'; exec sleep 20\"",
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false, CreateNoWindow = true
        })!;
        try {
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (!File.Exists(ready)) { await Task.Delay(20, guard.Token); }
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
                Assert.Equal("OCSP Response Status: successful", captured.Output);
                Assert.Equal("diagnostic", captured.Error);
            }
            Assert.True(process.HasExited);
        } finally {
            if (!process.HasExited) {
#if NET8_0_OR_GREATER
                process.Kill(entireProcessTree: true);
#else
                process.Kill();
#endif
                process.WaitForExit();
            }
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task NonInteractiveCaptureClosesStdinBeforeWaitingForExit() {
        using var process = Start("set /p answer= & echo received-eof", "read answer; printf received-eof");
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var captured = await Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, guard.Token);
        Assert.Equal("received-eof", captured.Output.Trim());
        Assert.True(process.HasExited);
    }

    [Fact]
    public async Task CapturesBothStreamsThroughExit() {
        using var process = Start("echo stdout & echo stderr 1>&2", "printf stdout; printf stderr >&2");
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var captured = await Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, guard.Token);
        Assert.True(process.HasExited);
        Assert.Equal("stdout", captured.Output.Trim());
        Assert.Equal("stderr", captured.Error.Trim());
    }

    [Fact]
    public async Task CancellationStopsOwnedChildAndDrainsItsStreams() {
        bool windows = Path.DirectorySeparatorChar == '\\';
        using var process = Process.Start(new ProcessStartInfo {
            FileName = windows ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ping.exe") : "/bin/sleep",
            Arguments = windows ? "-n 20 127.0.0.1" : "20",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Helpers.ProcessOutputCapture.ReadUntilExitAsync(process, cancellation.Token));
        Assert.True(process.HasExited);
    }

    private static Process Start(string windowsCommand, string posixCommand) {
        bool windows = Path.DirectorySeparatorChar == '\\';
        return Process.Start(new ProcessStartInfo {
            FileName = windows ? Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe" : "/bin/sh",
            Arguments = windows ? $"/d /q /c \"{windowsCommand}\"" : $"-c \"{posixCommand}\"",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
    }
}
