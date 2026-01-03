using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Gets apex A/AAAA analysis including PTR, FCrDNS, ASN and RPKI details.</summary>
/// <para>Analyzes apex addresses for SMTP fallback readiness, reverse DNS consistency, announcing ASN diversity, and RPKI validity.</para>
/// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
[Cmdlet(VerbsCommon.Get, "DDApexAddressInfo", DefaultParameterSetName = "ByName")]
[OutputType(typeof(DomainDetective.Views.ApexAddressInfo))]
public sealed class CmdletGetApexAddressInfo : ParallelAsyncPSCmdlet {
    /// <para>Domain(s) to analyze.</para>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = System.Array.Empty<string>();

    /// <para>DNS server used for queries.</para>
    [Parameter(Mandatory = false, Position = 1)]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Runs the apex address analysis.</summary>
    /// <returns>A task that represents the asynchronous operation.</returns>
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

            logger.WriteVerbose("Checking apex address info for domain: {0}", domain);
            await healthCheck.VerifyApexAddresses(domain, cancellationToken: CancelToken);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.ApexAddressAnalysis);
            WriteObject(view);
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}
