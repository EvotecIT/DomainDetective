using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective.PowerShell;

/// <summary>Classifies a domain's mail role based on DNS signals.</summary>
/// <para>Performs SPF, DKIM, MX, MTA-STS, TLS-RPT, DANE(SMTP) and BIMI checks to infer if the domain sends, receives, both, or is parked.</para>
/// <example>
///   <summary>Classify a single domain</summary>
///   <prefix>PS&gt; </prefix>
///   <code>Get-DDMailDomainClassification -DomainName example.com</code>
///   <para>Returns category, confidence, signals, score, and RFC references.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDMailDomainClassification", DefaultParameterSetName = "ByName")]
[OutputType(typeof(MailDomainClassificationResult))]
public sealed class CmdletGetMailDomainClassification : AsyncPSCmdlet {
    /// <para>Domain to analyze.</para>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string DomainName;

    /// <para>DNS server used for queries.</para>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ByName")]
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
        var classifier = new MailDomainClassifier(_healthCheck, _logger);
        var result = await classifier.ClassifyAsync(DomainName);
        WriteObject(result);
    }
}
