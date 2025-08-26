using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Queries DNSBL providers to see if domains or IPs are listed.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check a single host.</summary>
    ///   <code>Test-DDDnsBlacklist -NameOrIpAddress example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsBlacklist", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsBlacklist", "Test-DnsDomainBlacklist", "Test-DDDnsDomainBlacklist", "Test-DDDnsBlacklistRecord")]
    public sealed class CmdletTestDnsBlacklist : ExportableAsyncPSCmdlet {
        /// <para>Domain names or IP addresses to check.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string[] NameOrIpAddress;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Return full analysis result.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;
        /// <para>Return only blacklisted results.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter BlacklistedOnly { get; set; }

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;
        /// <para>Force domain-mode queries (domain + MX IPs).</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter TreatAsDomain { get; set; }

        /// <para>Force IP-mode queries (input must be IP).</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter TreatAsIp { get; set; }

        /// <para>Max concurrency hint for resolver (if supported).</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public int? MaxConcurrency { get; set; }

        /// <summary>
        /// Prepares the DNSBL health check and logging.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            // Initialize the logger to be able to see verbose, warning, debug, error, progress, and information messages.
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            // initialize the health check object
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            if (MaxConcurrency.HasValue) {
                if (!healthCheck.DnsConfiguration.SupportsResolverConcurrency) {
                    throw new ParameterBindingException("DnsClientX does not expose a concurrency hint in this build. Please update DnsClientX and DomainDetective, or omit -MaxConcurrency.");
                }
                healthCheck.DnsConfiguration.ResolverMaxConcurrency = MaxConcurrency.Value;
            }
            return Task.CompletedTask;
        }
        /// <summary>
        /// Checks the specified host names or IP addresses against DNSBL lists.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying DNSBL BlackLists for names/ip addresses: {0}", string.Join(", ", NameOrIpAddress));
            if (TreatAsDomain && TreatAsIp) {
                throw new ParameterBindingException("Specify only one of -TreatAsDomain or -TreatAsIp.");
            }

            if (TreatAsIp) {
                // All entries must be valid IPs
                foreach (var input in NameOrIpAddress) {
                    if (!System.Net.IPAddress.TryParse(input, out _)) {
                        throw new ParameterBindingException($"Input '{input}' is not a valid IP address but -TreatAsIp was specified.");
                    }
                }
                healthCheck.DNSBLAnalysis.Reset();
                await healthCheck.DNSBLAnalysis.AnalyzeDNSBLRecordsMany(NameOrIpAddress, _logger, clearExisting: true);
            } else if (TreatAsDomain) {
                // Domain path: domain lists + MX IPs
                healthCheck.DNSBLAnalysis.Reset();
                foreach (var input in NameOrIpAddress) {
                    await healthCheck.VerifyDNSBL(input);
                }
            } else {
                await healthCheck.CheckDNSBL(NameOrIpAddress);
            }

            if (NameOrIpAddress.Length == 1) {
                var input = NameOrIpAddress[0];
                var isIp = System.Net.IPAddress.TryParse(input, out _);

                if (FullResponse) {
                    // For domains, return full dictionary (domain + MX-IP) to give complete context
                    if (isIp) {
                        var res = healthCheck.DNSBLAnalysis.Results[input];
                        if (!BlacklistedOnly || res.IsBlacklisted) {
                            WriteObject(res);
                        }
                    } else {
                        var dict = healthCheck.DNSBLAnalysis.Results;
                        if (BlacklistedOnly) {
                            var filtered = dict.Where(kv => kv.Value.IsBlacklisted).ToDictionary(k => k.Key, v => v.Value);
                            WriteObject(filtered);
                        } else {
                            WriteObject(dict);
                        }
                    }
                } else {
                    // Flatten domain + MX-IP DNSBL records when domain is provided
                    if (isIp) {
                        var records = healthCheck.DNSBLAnalysis.Results[input].DNSBLRecords;
                        if (BlacklistedOnly) records = records.Where(r => r.IsBlackListed);
                        WriteObject(records);
                    } else {
                        var records = healthCheck.DNSBLAnalysis.Results.Values.SelectMany(r => r.DNSBLRecords);
                        if (BlacklistedOnly) records = records.Where(r => r.IsBlackListed);
                        var list = records.ToList();
                        WriteObject(list);
                    }
                }
            } else {
                if (FullResponse) {
                    var dict = healthCheck.DNSBLAnalysis.Results;
                    if (BlacklistedOnly) {
                        var filtered = dict.Where(kv => kv.Value.IsBlacklisted).ToDictionary(k => k.Key, v => v.Value);
                        WriteObject(filtered);
                    } else {
                        WriteObject(dict);
                    }
                } else {
                    var dnsblRecords = healthCheck.DNSBLAnalysis.Results.Values.SelectMany(result => result.DNSBLRecords);
                    if (BlacklistedOnly) dnsblRecords = dnsblRecords.Where(r => r.IsBlackListed);
                    WriteObject(dnsblRecords.ToList());
                }
            }
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
