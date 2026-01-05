using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.DesiredState;
using Xunit;
#if !NET472
using DomainDetective.PowerShell;
using Pwsh = System.Management.Automation.PowerShell;
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
    [IntegrationFact]
    public void DslScriptBlock_BuildsConfiguration() {
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletNewDesiredState).Assembly.Location).Invoke();
        ps.Commands.Clear();

        ps.AddScript(@"
$cfg = New-DDDesiredState {
  New-DDDesiredStateDmarc -Enabled $true
  New-DDDesiredStateSpf -Enabled $true
}
$cfg
");
        var results = ps.Invoke();

        Assert.False(ps.HadErrors);
        var config = results.Single().BaseObject as DesiredStateConfiguration;
        Assert.NotNull(config);
        Assert.True(config.Defaults.Dmarc?.Enabled ?? false);
        Assert.True(config.Defaults.Spf?.Enabled ?? false);
    }

    [IntegrationFact]
    public void TestDesiredStateCmdlet_Executes_EndToEnd() {
        var domain = GetIntegrationDomain().Replace("'", "''");
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletTestDesiredState).Assembly.Location).Invoke();
        ps.Commands.Clear();

        ps.AddScript($@"
$cfg = New-DDDesiredState {{
  New-DDDesiredStateDmarc -Enabled $true
  New-DDDesiredStateSpf -Enabled $true
  New-DDDesiredStateDkim -Enabled $true
}}
Test-DDDesiredState -DomainName '{domain}' -Configuration $cfg
");

        var results = ps.Invoke();
        Assert.False(ps.HadErrors);
        Assert.NotEmpty(results);
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
                        DomainPatterns = new[] { $"*.{domain}" },
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
