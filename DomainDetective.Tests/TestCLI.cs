using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace DomainDetective.Tests {
    public class TestCLI {
        [Fact]
        public void ShowsUsageWithoutArguments() {
            var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
            var project = Path.Combine(repoRoot, "DomainDetective.CLI", "DomainDetective.CLI.csproj");

            var psi = new ProcessStartInfo("dotnet", $"run --project \"{project}\"") {
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = Process.Start(psi);
            process.WaitForExit(60000);

            var output = process.StandardOutput.ReadToEnd();
            Assert.NotEqual(0, process.ExitCode);
            Assert.Contains("Usage", output);
        }
    }
}


