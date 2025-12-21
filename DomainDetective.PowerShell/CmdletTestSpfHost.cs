using DnsClientX;
using System;
using System.Management.Automation;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Tests an IP/sender/HELO against a domain's SPF policy.</summary>
    /// <para>Evaluates SPF mechanisms including ip4/ip6, a, mx, exists (with macro expansion), include and redirect.</para>
    /// <para>Returns a structured result with verdict, matched token, source domain, resolution chain and lookup count.</para>
    /// <example>
    ///   <summary>Evaluate an IP against SPF.</summary>
    ///   <code>Test-DDSpfHost -DomainName example.com -IpAddress 192.0.2.10 -Sender postmaster@example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDSpfHost", DefaultParameterSetName = "ByDomain")]
    [Alias("Test-SpfHost")]
    [OutputType(typeof(DomainDetective.SpfHostEvaluation))]
    public sealed class CmdletTestSpfHost : ParallelAsyncPSCmdlet {
        /// <para>Domain(s) to evaluate.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByDomain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = System.Array.Empty<string>();

        /// <para>IPv4/IPv6 address of the host to test.</para>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ByDomain")]
        [ValidateNotNullOrEmpty]
        public string IpAddress = string.Empty;

        /// <para>RFC 5322 Sender used for macro expansion (defaults to postmaster@domain).</para>
        [Parameter(Mandatory = false)]
        public string Sender = string.Empty;

        /// <para>HELO/EHLO domain used for macro expansion (defaults to mail.&lt;domain&gt;).</para>
        [Parameter(Mandatory = false)]
        public string Helo = string.Empty;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false)]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Optional raw SPF record to evaluate instead of querying DNS.</para>
        [Parameter(Mandatory = false)]
        public string TestSpfRecord = string.Empty;

        /// <para>Emit JSON instead of an object.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter AsJson;

        /// <summary>Evaluates the provided host against the domain's SPF policy.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            if (!IPAddress.TryParse(IpAddress, out var ip)) {
                ThrowTerminatingError(new ErrorRecord(new ArgumentException("Invalid IP address."), "InvalidIp", ErrorCategory.InvalidArgument, IpAddress));
                return;
            }

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

                if (!string.IsNullOrWhiteSpace(TestSpfRecord)) {
                    healthCheck.SpfAnalysis.Subject = domain;
                    await healthCheck.CheckSPF(TestSpfRecord, cancellationToken: CancelToken);
                } else {
                    await healthCheck.VerifySPF(domain, cancellationToken: CancelToken);
                }

                var sender = string.IsNullOrWhiteSpace(Sender) ? $"postmaster@{domain}" : Sender;
                var helo = string.IsNullOrWhiteSpace(Helo) ? $"mail.{domain}" : Helo;
                var eval = await healthCheck.SpfAnalysis.EvaluateHostAsync(domain, ip, sender, helo, logger);

                if (AsJson.IsPresent) {
                    var json = System.Text.Json.JsonSerializer.Serialize(eval, DomainDetective.Helpers.JsonOptions.Default);
                    WriteObject(json);
                } else {
                    WriteObject(eval);
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
