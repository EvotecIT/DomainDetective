using System.Diagnostics;

namespace DomainDetective.Tests;

public class TestProcessOutputCapture {
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
