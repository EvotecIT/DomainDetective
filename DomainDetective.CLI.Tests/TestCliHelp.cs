using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DomainDetective.CLI;
using System.Runtime.Versioning;
using Xunit;

namespace DomainDetective.CLI.Tests;

public class TestCliHelp
{
    private static async Task<string> CaptureOutputAsync(params string[] args)
    {
        var startInfo = new ProcessStartInfo {
            FileName = "dotnet",
            Arguments = BuildArguments(GetCliAssemblyPath(), args),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo);
        Assert.NotNull(process);

        var output = await process!.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        var error = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);

        Assert.True(
            process.ExitCode == 0,
            $"CLI exited with code {process.ExitCode}.{Environment.NewLine}{error}{output}");

        return Regex.Replace(output + error, @"\u001b\[[0-9;]*[A-Za-z]", string.Empty);
    }

    private static string GetCliAssemblyPath()
    {
        var repositoryRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        var targetFramework = GetTargetFramework();
        foreach (var configuration in new[] { "Release", "Debug" }) {
            var cliAssemblyPath = Path.Combine(
                repositoryRoot,
                "DomainDetective.CLI",
                "bin",
                configuration,
                targetFramework,
                "DomainDetective.CLI.dll");
            if (File.Exists(cliAssemblyPath)) {
                return cliAssemblyPath;
            }
        }

        throw new FileNotFoundException($"Unable to locate DomainDetective.CLI.dll for {targetFramework}.");
    }

    private static string GetTargetFramework()
    {
        var frameworkName = typeof(TestCliHelp).Assembly
            .GetCustomAttribute<TargetFrameworkAttribute>()?
            .FrameworkName;

        if (string.IsNullOrWhiteSpace(frameworkName)) {
            throw new InvalidOperationException("Unable to determine test target framework.");
        }

        if (frameworkName.Contains("v8.0", StringComparison.OrdinalIgnoreCase)) {
            return "net8.0";
        }

        if (frameworkName.Contains("v10.0", StringComparison.OrdinalIgnoreCase)) {
            return "net10.0";
        }

        throw new InvalidOperationException($"Unsupported framework '{frameworkName}'.");
    }

    private static string BuildArguments(string cliAssemblyPath, string[] args)
    {
        var quotedArgs = args.Select(QuoteArgument);
        return string.Join(" ", new[] { QuoteArgument(cliAssemblyPath) }.Concat(quotedArgs));
    }

    private static string QuoteArgument(string value)
    {
        if (string.IsNullOrEmpty(value)) {
            return "\"\"";
        }

        return value.IndexOfAny(new[] { ' ', '\t', '"' }) >= 0
            ? "\"" + value.Replace("\"", "\\\"") + "\""
            : value;
    }

    [Fact]
    public async Task RootHelp_IncludesExamples()
    {
        var output = await CaptureOutputAsync("--help");
        Assert.Contains("EXAMPLES:", output);
        Assert.Contains("DomainDetective check example.com", output);
    }

}
