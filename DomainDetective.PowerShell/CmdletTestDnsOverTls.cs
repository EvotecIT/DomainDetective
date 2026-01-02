using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Detects DNS over TLS (DoT, RFC 7858) support on a domain's authoritative name servers.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check DNS over TLS support.</summary>
///   <code>Test-DDDnsOverTls -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsOverTls", DefaultParameterSetName = "Domain")]
[Alias("Test-DnsOverTls")]
public sealed class CmdletTestDnsOverTls : ExportableAsyncPSCmdlet {
    /// <summary>Domain(s) to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for discovery queries (NS/A/AAAA).</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "Domain")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Executes the cmdlet operation.</summary>
    protected override async Task ProcessRecordAsync() {
        async Task ProcessDomainAsync(string domain) {
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

            logger.WriteVerbose("Checking DNS over TLS support for domain: {0}", domain);
            await healthCheck.Verify(domain, new[] { HealthCheckType.DNSOVERTLS }, cancellationToken: CancelToken).ConfigureAwait(false);
            try
            {
                var view = DomainDetective.Views.Converters.Convert(healthCheck.DnsOverTlsAnalysis);
                WriteObject(view);
                if (IsExportRequested())
                {
                    await ExportNotImplementedAsync("Test-DDDnsOverTls").ConfigureAwait(false);
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
