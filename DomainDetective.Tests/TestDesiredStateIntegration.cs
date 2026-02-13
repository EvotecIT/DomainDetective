using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.DesiredState;
using Xunit;
#if !NET472
using DomainDetective.PowerShell;
#endif

namespace DomainDetective.Tests;

public sealed class TestDesiredStateIntegration {
    private static string GetIntegrationDomain() {
        var value = Environment.GetEnvironmentVariable("DOMAINDETECTIVE_INTEGRATION_DOMAIN");
        if (string.IsNullOrWhiteSpace(value)) {
            return "example.com";
        }
        return value.Trim();
    }

#if !NET472
    private sealed class PowerShellProcessResult {
        public int ExitCode { get; }
        public string StandardOutput { get; }
        public string StandardError { get; }

        public PowerShellProcessResult(int exitCode, string standardOutput, string standardError) {
            ExitCode = exitCode;
            StandardOutput = standardOutput;
            StandardError = standardError;
        }
    }

    private static PowerShellProcessResult RunPowerShellScript(string script, TimeSpan timeout) {
        var executable = ResolvePowerShellExecutable();
        var startInfo = new ProcessStartInfo {
            FileName = executable,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && string.Equals(executable, "powershell", StringComparison.OrdinalIgnoreCase)) {
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
        }
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        using var process = Process.Start(startInfo);
        if (process == null) {
            throw new InvalidOperationException($"Failed to start {executable}.");
        }

        var stdOutTask = process.StandardOutput.ReadToEndAsync();
        var stdErrTask = process.StandardError.ReadToEndAsync();
        var timeoutMs = (int)Math.Min(timeout.TotalMilliseconds, int.MaxValue);
        if (!process.WaitForExit(timeoutMs)) {
            try {
                process.Kill(entireProcessTree: true);
            } catch {
            }
            throw new TimeoutException($"PowerShell script exceeded timeout of {timeout}.");
        }

        Task.WaitAll(stdOutTask, stdErrTask);
        return new PowerShellProcessResult(process.ExitCode, stdOutTask.Result, stdErrTask.Result);
    }

    private static JsonElement RunPowerShellJson(string script, TimeSpan timeout) {
        var result = RunPowerShellScript(script, timeout);
        if (result.ExitCode != 0) {
            throw new InvalidOperationException($"PowerShell exited with {result.ExitCode}. StdErr: {result.StandardError}");
        }

        var json = ExtractLastNonEmptyLine(result.StandardOutput);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static string ExtractLastNonEmptyLine(string output) {
        if (string.IsNullOrWhiteSpace(output)) {
            throw new InvalidOperationException("PowerShell output is empty.");
        }

        var lines = output
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .ToArray();
        if (lines.Length == 0) {
            throw new InvalidOperationException("PowerShell output did not contain any data.");
        }

        return lines[^1];
    }

    private static string ResolvePowerShellExecutable() {
        if (CommandExists("pwsh")) {
            return "pwsh";
        }
        if (CommandExists("powershell")) {
            return "powershell";
        }

        throw new InvalidOperationException("PowerShell executable not found on PATH.");
    }

    private static bool CommandExists(string command) {
        var checker = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "where" : "which";
        var startInfo = new ProcessStartInfo {
            FileName = checker,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add(command);

        using var process = Process.Start(startInfo);
        if (process == null) {
            return false;
        }

        process.WaitForExit(2000);
        return process.ExitCode == 0;
    }

    private static string EscapePowerShellString(string value) {
        return value.Replace("'", "''");
    }

    [IntegrationFact]
    public void DslScriptBlock_BuildsConfiguration() {
        var modulePath = typeof(CmdletNewDesiredState).Assembly.Location;
        Assert.False(string.IsNullOrWhiteSpace(modulePath));
        var escapedModule = EscapePowerShellString(modulePath);

        var script = $@"
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
Import-Module '{escapedModule}'
$cfg = New-DDDesiredState {{
  New-DDDesiredStateDmarc -Enabled $true
  New-DDDesiredStateSpf -Enabled $true
}}
[pscustomobject]@{{
  DmarcEnabled = $cfg.Defaults.Dmarc.Enabled
  SpfEnabled = $cfg.Defaults.Spf.Enabled
}} | ConvertTo-Json -Compress
";

        var payload = RunPowerShellJson(script, TimeSpan.FromMinutes(2));
        Assert.True(payload.GetProperty("DmarcEnabled").GetBoolean());
        Assert.True(payload.GetProperty("SpfEnabled").GetBoolean());
    }

    [IntegrationFact]
    public void TestDesiredStateCmdlet_Executes_EndToEnd() {
        var modulePath = typeof(CmdletTestDesiredState).Assembly.Location;
        Assert.False(string.IsNullOrWhiteSpace(modulePath));
        var escapedModule = EscapePowerShellString(modulePath);
        var domain = EscapePowerShellString(GetIntegrationDomain());

        var script = $@"
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
Import-Module '{escapedModule}'
$cfg = New-DDDesiredState {{
  New-DDDesiredStateDmarc -Enabled $true
  New-DDDesiredStateSpf -Enabled $true
  New-DDDesiredStateDkim -Enabled $true
}}
$results = Test-DDDesiredState -DomainName '{domain}' -Configuration $cfg
[pscustomobject]@{{ Count = @($results).Count }} | ConvertTo-Json -Compress
";

        var payload = RunPowerShellJson(script, TimeSpan.FromMinutes(5));
        Assert.True(payload.GetProperty("Count").GetInt32() > 0);
    }
#endif

    [IntegrationFact]
    public async Task MailClassification_Overrides_Apply() {
        var domain = GetIntegrationDomain();
        var logger = new InternalLogger(false);
        var healthCheck = new DomainHealthCheck(DnsEndpoint.System, logger);
        var classifier = new MailDomainClassifier(healthCheck, logger);

        var classificationResult = await classifier.ClassifyAsync(domain, CancellationToken.None);
        Assert.NotNull(classificationResult);

        var config = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile(),
            Overrides = new System.Collections.Generic.List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { domain },
                        Classifications = new[] { classificationResult.Classification }
                    },
                    Profile = new DesiredStateProfile {
                        Dmarc = new DesiredStateDmarcPolicy {
                            Enabled = true,
                            RequireRecord = true
                        }
                    }
                }
            }
        };

        var resolved = config.ResolveProfile(domain, classificationResult.Classification);
        Assert.True(resolved.Dmarc?.RequireRecord ?? false);
    }

    [IntegrationFact]
    public async Task AllPolicies_Run_With_RealDns() {
        var domain = GetIntegrationDomain();
        var logger = new InternalLogger(false);
        var healthCheck = new DomainHealthCheck(DnsEndpoint.System, logger);
        var execution = new HealthCheckExecutionOptions {
            EnableParallelism = true,
            MaxParallelism = 8,
            DnsParallelism = 8,
            SkipBimiIndicatorDownload = true
        };

        var profile = CreateAllPoliciesProfile();
        var checks = DesiredStateConfiguration.GetRequiredChecks(profile);

        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        await healthCheck.Verify(domain, healthCheckTypes: checks, cancellationToken: cts.Token, executionOptions: execution);

        var analysis = DesiredStateEvaluator.Evaluate(domain, healthCheck, profile, options: new DesiredStateEvaluationOptions {
            LogExceptionsAsErrors = true
        });

        Assert.NotNull(analysis);
        Assert.NotEmpty(analysis.Assessments);
    }

    private static DesiredStateProfile CreateAllPoliciesProfile() {
        return new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy { Enabled = true },
            Spf = new DesiredStateSpfPolicy { Enabled = true },
            Dkim = new DesiredStateDkimPolicy { Enabled = true },
            Mtasts = new DesiredStateMtastsPolicy { Enabled = true },
            TlsRpt = new DesiredStateTlsRptPolicy { Enabled = true },
            Bimi = new DesiredStateBimiPolicy { Enabled = true, SkipIndicatorDownload = true },
            Mx = new DesiredStateMxPolicy { Enabled = true },
            StartTls = new DesiredStateStartTlsPolicy { Enabled = true },
            SmtpTls = new DesiredStateMailTlsPolicy { Enabled = true },
            ImapTls = new DesiredStateMailTlsPolicy { Enabled = true },
            Pop3Tls = new DesiredStateMailTlsPolicy { Enabled = true },
            SmtpBanner = new DesiredStateSmtpBannerPolicy { Enabled = true },
            SmtpAuth = new DesiredStateSmtpAuthPolicy { Enabled = true },
            OpenRelay = new DesiredStateOpenRelayPolicy { Enabled = true },
            OpenResolver = new DesiredStateOpenResolverPolicy { Enabled = true },
            MailLatency = new DesiredStateMailLatencyPolicy { Enabled = true },
            Autodiscover = new DesiredStateAutodiscoverPolicy { Enabled = true },
            ReverseDns = new DesiredStateReverseDnsPolicy { Enabled = true },
            FcrDns = new DesiredStateFcrDnsPolicy { Enabled = true },
            Ns = new DesiredStateNsPolicy { Enabled = true },
            DanglingCname = new DesiredStateDanglingCnamePolicy { Enabled = true },
            Caa = new DesiredStateCaaPolicy { Enabled = true },
            DnsSec = new DesiredStateDnssecPolicy { Enabled = true },
            Soa = new DesiredStateSoaPolicy { Enabled = true },
            Dane = new DesiredStateDanePolicy { Enabled = true },
            Dnsbl = new DesiredStateDnsblPolicy { Enabled = true },
            DnsHealth = new DesiredStateDnsHealthPolicy { Enabled = true },
            ApexAddress = new DesiredStateApexAddressPolicy { Enabled = true },
            Rpki = new DesiredStateRpkiPolicy { Enabled = true },
            EdnsSupport = new DesiredStateEdnsSupportPolicy { Enabled = true },
            DnsOverTls = new DesiredStateDnsOverTlsPolicy { Enabled = true },
            FlatteningService = new DesiredStateFlatteningServicePolicy { Enabled = true },
            Delegation = new DesiredStateDelegationPolicy { Enabled = true },
            ZoneTransfer = new DesiredStateZoneTransferPolicy { Enabled = true },
            WildcardDns = new DesiredStateWildcardDnsPolicy { Enabled = true },
            Ttl = new DesiredStateTtlPolicy { Enabled = true },
            SecurityTxt = new DesiredStateSecurityTxtPolicy { Enabled = true },
            Robots = new DesiredStateRobotsPolicy { Enabled = true }
        };
    }
}
