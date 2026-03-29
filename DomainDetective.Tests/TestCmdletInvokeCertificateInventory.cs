#if !NET472
using System;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using DomainDetective.PowerShell;
using Pwsh = System.Management.Automation.PowerShell;

namespace DomainDetective.Tests;

public sealed class TestCmdletInvokeCertificateInventory {
    [Fact]
    public void GetWarningTargetDecisionBuckets_ReturnsOnlyWarningSeverityEntries() {
        IReadOnlyList<TargetDecisionSummaryEntry> result = CmdletInvokeCertificateInventory.GetWarningTargetDecisionBuckets(new[] {
            new TargetDecisionSummaryEntry {
                Stage = "additional-endpoints",
                Action = "rejected",
                Reason = "unsupported-scheme",
                Severity = "warning",
                Count = 1
            },
            new TargetDecisionSummaryEntry {
                Stage = "target-limit",
                Action = "pruned",
                Reason = "max-targets",
                Severity = "informational",
                Count = 2
            }
        });

        TargetDecisionSummaryEntry warning = Assert.Single(result);
        Assert.Equal("unsupported-scheme", warning.Reason);
    }

    [Fact]
    public void FormatWarningTargetDecisionBucket_IncludesRecommendedAction() {
        string message = CmdletInvokeCertificateInventory.FormatWarningTargetDecisionBucket(new TargetDecisionSummaryEntry {
            Stage = "additional-endpoints",
            Action = "rejected",
            Reason = "unsupported-scheme",
            Severity = "warning",
            Count = 3,
            RecommendedAction = "Use a supported HTTPS or mail endpoint scheme."
        });

        Assert.Contains("additional-endpoints/rejected/unsupported-scheme", message, StringComparison.Ordinal);
        Assert.Contains("affected 3 item(s)", message, StringComparison.Ordinal);
        Assert.Contains("Use a supported HTTPS or mail endpoint scheme.", message, StringComparison.Ordinal);
    }

    [Fact]
    public void InvokeDdCertificateInventory_EmitsWarningTargetDecisionMessagesWithoutStrictMode() {
#if NET8_0
        ExternalPowerShellInvocationResult invocation = InvokeCertificateInventoryViaExternalPowerShell(strictMode: false);

        Assert.Equal(0, invocation.ExitCode);
        Assert.Equal("success", invocation.Status);
        Assert.Contains(
            invocation.WarningMessages,
            static warning => warning.Contains("Target decision warning:", StringComparison.Ordinal));
        Assert.True(invocation.HasResult);
#else
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletInvokeCertificateInventory).Assembly.Location).Invoke();
        ps.Commands.Clear();
        ps.AddCommand("Invoke-DDCertificateInventory")
            .AddParameter("DomainName", "example.com")
            .AddParameter("NoApexHttps")
            .AddParameter("NoWwwHttps")
            .AddParameter("DisableMxDiscovery")
            .AddParameter("DisableSmtpStartTls")
            .AddParameter("DisableSubmissionStartTls")
            .AddParameter("NoPersist")
            .AddParameter("Endpoint", "ftp://example.com");

        var results = ps.Invoke();

        Assert.Empty(ps.Streams.Error);
        Assert.Single(results);
        Assert.Contains(
            ps.Streams.Warning.Select(static record => record.Message),
            static warning => warning.Contains("Target decision warning:", StringComparison.Ordinal));
#endif
    }

    [Fact]
    public void InvokeDdCertificateInventory_ThrowsWhenWarningTargetDecisionsPresentInStrictMode() {
#if NET8_0
        ExternalPowerShellInvocationResult invocation = InvokeCertificateInventoryViaExternalPowerShell(strictMode: true);

        Assert.Equal(1, invocation.ExitCode);
        Assert.Equal("error", invocation.Status);
        Assert.Contains(
            invocation.WarningMessages,
            static warning => warning.Contains("Target decision warning:", StringComparison.Ordinal));
        Assert.Contains("CertificateInventoryTargetDecisionWarningsDetected", invocation.ErrorId, StringComparison.Ordinal);
#else
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletInvokeCertificateInventory).Assembly.Location).Invoke();
        ps.Commands.Clear();
        ps.AddCommand("Invoke-DDCertificateInventory")
            .AddParameter("DomainName", "example.com")
            .AddParameter("NoApexHttps")
            .AddParameter("NoWwwHttps")
            .AddParameter("DisableMxDiscovery")
            .AddParameter("DisableSmtpStartTls")
            .AddParameter("DisableSubmissionStartTls")
            .AddParameter("NoPersist")
            .AddParameter("FailOnWarningTargetDecisions")
            .AddParameter("Endpoint", "ftp://example.com");

        var exception = Assert.Throws<System.Management.Automation.CmdletInvocationException>(() => ps.Invoke());

        Assert.Contains("Warning-level target decisions detected", exception.Message, StringComparison.Ordinal);
        Assert.NotNull(exception.InnerException);
        Assert.Contains("Warning-level target decisions detected", exception.InnerException!.Message, StringComparison.Ordinal);
        Assert.Contains(
            ps.Streams.Warning.Select(static record => record.Message),
            static warning => warning.Contains("Target decision warning:", StringComparison.Ordinal));
#endif
    }

#if NET8_0
    private sealed class ExternalPowerShellInvocationResult {
        public int ExitCode { get; set; }
        public string Status { get; init; } = string.Empty;
        public string ErrorId { get; init; } = string.Empty;
        public string ErrorMessage { get; init; } = string.Empty;
        public bool HasResult { get; init; }
        public string[] WarningMessages { get; init; } = Array.Empty<string>();
    }

    private static ExternalPowerShellInvocationResult InvokeCertificateInventoryViaExternalPowerShell(bool strictMode) {
        string modulePath = typeof(CmdletInvokeCertificateInventory).Assembly.Location;
        string escapedModulePath = modulePath.Replace("'", "''", StringComparison.Ordinal);
        string strictSwitch = strictMode ? "-FailOnWarningTargetDecisions" : string.Empty;
        string script = $@"
$WarningMessages = @()
$result = $null
$status = 'success'
$errorId = ''
$errorMessage = ''
Import-Module '{escapedModulePath}' -ErrorAction Stop
try {{
    $result = Invoke-DDCertificateInventory -DomainName example.com -NoApexHttps -NoWwwHttps -DisableMxDiscovery -DisableSmtpStartTls -DisableSubmissionStartTls -NoPersist -Endpoint 'ftp://example.com' {strictSwitch} -WarningVariable +WarningMessages -ErrorAction Stop
}} catch {{
    $status = 'error'
    $errorId = $_.FullyQualifiedErrorId
    $errorMessage = $_.Exception.Message
}}
[pscustomobject]@{{
    Status = $status
    ErrorId = $errorId
    ErrorMessage = $errorMessage
    HasResult = $null -ne $result
    WarningMessages = @($WarningMessages | ForEach-Object {{ $_.ToString() }})
}} | ConvertTo-Json -Depth 6 -Compress
if ($status -eq 'error') {{
    exit 1
}}";

        var startInfo = new ProcessStartInfo {
            FileName = "pwsh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        using var process = Process.Start(startInfo);
        Assert.NotNull(process);

        string standardOutput = process!.StandardOutput.ReadToEnd();
        string standardError = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(30000), "External PowerShell invocation exceeded timeout.");

        string json = standardOutput
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(static line => line.Trim())
            .Last(static line => line.StartsWith("{", StringComparison.Ordinal));

        var result = JsonSerializer.Deserialize<ExternalPowerShellInvocationResult>(json);
        Assert.NotNull(result);
        Assert.True(string.IsNullOrWhiteSpace(standardError), standardError);

        result!.ExitCode = process.ExitCode;
        return result;
    }
#endif
}
#endif
