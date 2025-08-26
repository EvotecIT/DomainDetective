using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Gets apex A/AAAA analysis including PTR, FCrDNS, ASN and RPKI details.</summary>
/// <para>Analyzes apex addresses for SMTP fallback readiness, reverse DNS consistency, announcing ASN diversity, and RPKI validity.</para>
[Cmdlet(VerbsCommon.Get, "DDApexAddressInfo", DefaultParameterSetName = "ByName")]
[OutputType(typeof(ApexAddressAnalysis))]
public sealed class CmdletGetApexAddressInfo : AsyncPSCmdlet {
    /// <para>Domain to analyze.</para>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string DomainName;

    /// <para>DNS server used for queries.</para>
    [Parameter(Mandatory = false, Position = 1)]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    private InternalLogger _logger;
    private DomainHealthCheck _healthCheck;

    protected override Task BeginProcessingAsync() {
        _logger = new InternalLogger(false);
        var internalLoggerPowerShell = new InternalLoggerPowerShell(
            _logger,
            this.WriteVerbose,
            this.WriteWarning,
            this.WriteDebug,
            this.WriteError,
            this.WriteProgress,
            this.WriteInformation);
        internalLoggerPowerShell.ResetActivityIdCounter();
        _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        return Task.CompletedTask;
    }

    protected override async Task ProcessRecordAsync() {
        await _healthCheck.VerifyApexAddresses(DomainName);
        WriteObject(_healthCheck.ApexAddressAnalysis);
    }
}

