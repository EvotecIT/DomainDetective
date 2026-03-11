using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Evaluates DNS amplification posture for a domain's authoritative name servers.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check DNS amplification posture.</summary>
///   <code>Test-DDDnsAmplification -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsAmplification", DefaultParameterSetName = "Domain")]
[Alias("Test-DnsAmplification")]
public sealed class CmdletTestDnsAmplification : ExportableAsyncPSCmdlet
{
    /// <summary>Domain(s) to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for discovery queries (NS/A/AAAA).</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "Domain")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Executes the cmdlet operation.</summary>
    protected override async Task ProcessRecordAsync()
    {
        async Task ProcessDomainAsync(string domain)
        {
            var logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();

            var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
            ApplyExecutionOptions(healthCheck);

            logger.WriteVerbose("Checking DNS amplification posture for domain: {0}", domain);
            await healthCheck.Verify(domain, new[] { HealthCheckType.DNSAMPLIFICATION }, cancellationToken: CancelToken).ConfigureAwait(false);
            try
            {
                var view = DomainDetective.Views.Converters.Convert(healthCheck.DnsAmplificationAnalysis);
                WriteObject(view);
                if (IsExportRequested())
                {
                    try
                    {
                        var hadUnsupportedFormats = false;
                        CompositionExportHelper.WriteReports(
                            new System.Collections.Generic.List<object> { view },
                            GetRequestedFormatsOrDefault(ExportDefaults.Format),
                            ExportPath,
                            domain,
                            DomainDetective.Reports.ReportScope.Normal,
                            $"DNS Amplification Report — {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats)
                        {
                            await ExportNotImplementedAsync("Test-DDDnsAmplification").ConfigureAwait(false);
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarning($"DNS amplification export failed: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(ex, "DomainDetective.ConvertFailed", ErrorCategory.InvalidData, domain));
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync).ConfigureAwait(false);
    }
}
