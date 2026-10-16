using System.Diagnostics;

namespace DomainDetective.Tests;

public class TestProcessOutputCapture {
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
        using var process = Start("set /p answer=waiting", "read answer");
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
