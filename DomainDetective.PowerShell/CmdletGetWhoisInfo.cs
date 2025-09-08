using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Linq;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves WHOIS information for the specified domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Get WHOIS details.</summary>
    ///   <code>Get-DDDomainWhois -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsCommon.Get, "DDDomainWhois", DefaultParameterSetName = "ServerName")]
[Alias("Get-DomainWhois")]
    public sealed class CmdletGetWhoisInfo : AsyncPSCmdlet {
        /// <para>Domain to retrieve WHOIS information for.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Directory used to store WHOIS snapshots.</para>
        [Parameter(Mandatory = false)]
        public string SnapshotPath = string.Empty;

        /// <para>Return changes since last snapshot.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter Diff;

        /// <para>Follow registrar WHOIS referrals when available.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter FollowReferral;

        /// <para>Maximum referral depth when -FollowReferral is used (default 2).</para>
        [Parameter(Mandatory = false)]
        public int MaxReferralDepth = 2;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>
        /// Sets up logging and initializes WHOIS analysis.
        /// </summary>
        /// <returns>A completed task.</returns>
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

        /// <summary>
        /// Retrieves WHOIS data and optionally stores snapshots.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying WHOIS information for domain: {0}", DomainName);
            _healthCheck.WhoisAnalysis.FollowReferral = FollowReferral.IsPresent;
            _healthCheck.WhoisAnalysis.MaxReferralDepth = MaxReferralDepth <= 0 ? 2 : MaxReferralDepth;
            await _healthCheck.CheckWHOIS(DomainName);
            if (!string.IsNullOrEmpty(SnapshotPath)) {
                _healthCheck.WhoisAnalysis.SnapshotDirectory = SnapshotPath;
                var changes = Diff.IsPresent ? _healthCheck.WhoisAnalysis.GetWhoisChanges().ToList() : null;
                _healthCheck.WhoisAnalysis.SaveSnapshot();
                if (Diff.IsPresent && changes != null && changes.Count > 0) {
                    WriteObject(changes, true);
                }
            }
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.WhoisAnalysis);
            WriteObject(view);
        }
    }
}
