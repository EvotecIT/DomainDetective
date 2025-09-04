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
    public sealed class CmdletTestSpfHost : AsyncPSCmdlet {
        /// <para>Domain to evaluate.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByDomain")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <para>IPv4/IPv6 address of the host to test.</para>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ByDomain")]
        [ValidateNotNullOrEmpty]
        public string IpAddress;

        /// <para>RFC 5322 Sender used for macro expansion (defaults to postmaster@domain).</para>
        [Parameter(Mandatory = false)]
        public string Sender;

        /// <para>HELO/EHLO domain used for macro expansion (defaults to mail.&lt;domain&gt;).</para>
        [Parameter(Mandatory = false)]
        public string Helo;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false)]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Optional raw SPF record to evaluate instead of querying DNS.</para>
        [Parameter(Mandatory = false)]
        public string TestSpfRecord;

        /// <para>Emit JSON instead of an object.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter AsJson;

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
            if (!IPAddress.TryParse(IpAddress, out var ip)) {
                ThrowTerminatingError(new ErrorRecord(new ArgumentException("Invalid IP address."), "InvalidIp", ErrorCategory.InvalidArgument, IpAddress));
            }

            if (!string.IsNullOrWhiteSpace(TestSpfRecord)) {
                _healthCheck.SpfAnalysis.Subject = DomainName;
                await _healthCheck.CheckSPF(TestSpfRecord);
            } else {
                await _healthCheck.VerifySPF(DomainName);
            }

            var sender = string.IsNullOrWhiteSpace(Sender) ? $"postmaster@{DomainName}" : Sender;
            var helo = string.IsNullOrWhiteSpace(Helo) ? $"mail.{DomainName}" : Helo;
            var eval = await _healthCheck.SpfAnalysis.EvaluateHostAsync(DomainName, ip, sender, helo, _logger);

            if (AsJson.IsPresent) {
                var json = System.Text.Json.JsonSerializer.Serialize(eval, DomainDetective.Helpers.JsonOptions.Default);
                WriteObject(json);
            } else {
                WriteObject(eval);
            }
        }
    }
}
