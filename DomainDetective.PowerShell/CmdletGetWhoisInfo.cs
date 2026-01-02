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
    public sealed class CmdletGetWhoisInfo : ParallelAsyncPSCmdlet {
        /// <para>Domain(s) to retrieve WHOIS information for.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

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

        /// <summary>
        /// Retrieves WHOIS data and optionally stores snapshots.
        /// </summary>
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

                logger.WriteVerbose("Querying WHOIS information for domain: {0}", domain);
                healthCheck.WhoisAnalysis.FollowReferral = FollowReferral.IsPresent;
                healthCheck.WhoisAnalysis.MaxReferralDepth = MaxReferralDepth <= 0 ? 2 : MaxReferralDepth;
                await healthCheck.CheckWHOIS(domain, cancellationToken: CancelToken);
                if (!string.IsNullOrEmpty(SnapshotPath)) {
                    healthCheck.WhoisAnalysis.SnapshotDirectory = SnapshotPath;
                    var changes = Diff.IsPresent ? healthCheck.WhoisAnalysis.GetWhoisChanges().ToList() : null;
                    healthCheck.WhoisAnalysis.SaveSnapshot();
                    if (Diff.IsPresent && changes != null && changes.Count > 0) {
                        WriteObject(changes, true);
                    }
                }
                var view = DomainDetective.Views.Converters.Convert(healthCheck.WhoisAnalysis);
                WriteObject(view);
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
