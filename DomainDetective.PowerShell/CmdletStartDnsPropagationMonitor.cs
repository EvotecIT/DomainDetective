using DnsClientX;
using DomainDetective.Monitoring;
using DomainDetective;
using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Reflection;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Starts background monitoring of DNS propagation.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Start monitoring an A record.</summary>
    ///   <code>Start-DDDnsPropagationMonitor -DomainName example.com -RecordType A -WebhookUrl https://example.com/webhook</code>
    /// </example>
    [Cmdlet(
        VerbsLifecycle.Start,
        "DDDnsPropagationMonitor",
        SupportsShouldProcess = false,
        DefaultParameterSetName = "File")]
    [Alias("Start-DnsPropagationMonitor")]
    public sealed class CmdletStartDnsPropagationMonitor : AsyncPSCmdlet {
        /// <summary>Domain(s) to monitor.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "File")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Custom")]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS record type.</summary>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "File")]
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "Custom")]
        public DnsRecordType RecordType;

        /// <summary>
        /// Path to JSON file with DNS servers. If omitted the file
        /// <c>Data/DNS/PublicDNS.json</c> in the module directory is used when present.
        /// </summary>
        [Parameter(Mandatory = false, ParameterSetName = "File")]
        public string? ServersFile;

        /// <summary>One or more custom DNS servers.</summary>
        [Parameter(Mandatory = false, ParameterSetName = "Custom")]
        public string[] DnsServer = Array.Empty<string>();

        /// <summary>Filter builtin servers by country.</summary>
        [Parameter(Mandatory = false)]
        public CountryId? Country;

        /// <summary>Filter builtin servers by location.</summary>
        [Parameter(Mandatory = false)]
        public LocationId? Location;

        /// <summary>Polling interval in seconds.</summary>
        [Parameter(Mandatory = false)]
        public int IntervalSeconds = 300;

        /// <summary>Webhook URL for notifications.</summary>
        [Parameter(Mandatory = false)]
        public string? WebhookUrl;

        /// <summary>Maximum concurrent DNS queries.</summary>
        [Parameter(Mandatory = false)]
        public int MaxParallelism = 0;

        /// <summary>
        /// Configures and starts the DNS propagation monitor.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            var moduleBase = this.MyInvocation.MyCommand.Module?.ModuleBase
                ?? Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
                ?? string.Empty;
            var defaultFile = Path.Combine(moduleBase, "Data", "DNS", "PublicDNS.json");
            var parsedServers = new List<PublicDnsEntry>();
            if (ParameterSetName == "Custom") {
                foreach (var ip in DnsServer) {
                    if (System.Net.IPAddress.TryParse(ip, out var parsed)) {
                        parsedServers.Add(new PublicDnsEntry { IPAddress = parsed, Enabled = true });
                    } else {
                        WriteWarning($"Invalid DNS server IP: {ip}");
                    }
                }
            }

            foreach (var domain in DomainName) {
                CancelToken.ThrowIfCancellationRequested();
                var monitor = new DnsPropagationMonitor {
                    Domain = domain,
                    RecordType = RecordType,
                    Interval = TimeSpan.FromSeconds(IntervalSeconds),
                    Country = Country,
                    Location = Location,
                    MaxParallelism = MaxParallelism
                };

                if (!string.IsNullOrWhiteSpace(ServersFile)) {
                    var path = Path.IsPathRooted(ServersFile)
                        ? ServersFile
                        : Path.Combine(moduleBase, ServersFile);
                    monitor.LoadServers(path);
                } else if (File.Exists(defaultFile)) {
                    monitor.LoadServers(defaultFile);
                } else {
                    monitor.LoadBuiltinServers();
                }

                if (ParameterSetName == "Custom" && parsedServers.Count > 0) {
                    foreach (var entry in parsedServers) {
                        monitor.AddServer(entry);
                    }
                }

                if (!string.IsNullOrWhiteSpace(WebhookUrl)) {
                    var url = WebhookUrl!; // guarded by IsNullOrWhiteSpace
                    monitor.Notifier = NotificationSenderFactory.CreateWebhook(url);
                }

                monitor.Start();
                WriteObject(monitor);
            }

            return Task.CompletedTask;
        }
    }
}

