using DnsClientX;
using DomainDetective;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Queries DNSBL providers to see if domains or IPs are listed.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Default behavior:
    /// - Domain inputs: queries domain blocklists and then resolves MX A/AAAA to query IP blocklists for each resulting IP.
    /// - IP inputs: queries IP blocklists directly.
    /// - Mixed arrays: aggregates both without clearing prior results.
    ///
    /// Overrides:
    /// - <c>-TreatAsDomain</c>: forces the "domain + MX-IP" path for the input(s).
    /// - <c>-TreatAsIp</c>: if an input is an IP it is checked as-is; if an input is a domain, its apex A/AAAA IPs are resolved and checked on IP blocklists.
    ///
    /// Fallback:
    /// - When MX exists but has no resolvable A/AAAA (or no MX is present), the cmdlet falls back to apex A/AAAA for IP blocklist checks.
    ///
    /// Output:
    /// - By default returns a flat list of DNSBLRecord across domain and any resolved IPs.
    /// - With <c>-FullResponse</c> returns a dictionary mapping each key (domain or IP) to a DNSQueryResult.
    /// - Use <c>-BlacklistedOnly</c> to filter output to listed results.
    ///
    /// Performance:
    /// - Use <c>-MaxConcurrency</c> to hint the DNS resolver concurrency (requires DnsClientX 1.0.1+).
    ///
    /// Domain IP scan control:
    /// - Use <c>-DomainIpScan</c> to control which IPs are resolved and checked when a domain is provided.
    ///   Values: <c>MxOnly</c>, <c>MxAOnly</c>, <c>MxAAAAOnly</c>, <c>ApexOnly</c>, <c>ApexAOnly</c>, <c>ApexAAAAOnly</c>, <c>MxAndApex</c>, <c>MxThenApexFallback</c> (default).
    ///
    /// Notes:
    /// - Export switches are available but dedicated reports are not yet implemented; using them will emit a TODO message.
    /// </remarks>
    /// <example>
    ///   <summary>Default: domain + MX-IP checks.</summary>
    ///   <code>Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -Verbose</code>
    /// </example>
    /// <example>
    ///   <summary>Force domain path explicitly (same as default for domains).</summary>
    ///   <code>Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -TreatAsDomain -Verbose</code>
    /// </example>
    /// <example>
    ///   <summary>Treat a domain as IP-only checks (apex A/AAAA).</summary>
    ///   <code>Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -TreatAsIp -Verbose</code>
    /// </example>
    /// <example>
    ///   <summary>Mixed inputs: domain + IP, return only listed hits.</summary>
    ///   <code>Test-DDDnsBlacklist -NameOrIpAddress 'example.com','203.0.113.10' -BlacklistedOnly</code>
    /// </example>
    /// <example>
    ///   <summary>Return the full mapping (domain and each IP as separate keys).</summary>
    ///   <code>$res = Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -FullResponse; $res['example.com']</code>
    /// </example>
    /// <example>
    ///   <summary>Increase resolver concurrency (requires DnsClientX 1.0.1+).</summary>
    ///   <code>Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -MaxConcurrency 64 -Verbose</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsBlacklist", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsBlacklist", "Test-DnsDomainBlacklist", "Test-DDDnsDomainBlacklist", "Test-DDDnsBlacklistRecord")]
    public sealed class CmdletTestDnsBlacklist : ExportableAsyncPSCmdlet {
        /// <para>Domain names or IP addresses to check.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string[] NameOrIpAddress = System.Array.Empty<string>();

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Return full analysis result.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;
        /// <para>Return only blacklisted results.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter BlacklistedOnly { get; set; }

        private InternalLogger _logger = null!;
        private DomainHealthCheck healthCheck = null!;
        /// <para>Force domain-mode queries (domain + MX IPs).</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter TreatAsDomain { get; set; }

        /// <para>Force IP-mode queries (input must be IP).</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter TreatAsIp { get; set; }

        /// <para>Max concurrency hint for resolver (if supported).</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public int? MaxConcurrency { get; set; }

        /// <para>Controls which IPs are resolved and checked for domains.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public DomainIpScanMode? DomainIpScan { get; set; }

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

            // Execution strategy
            // -TreatAsIp: query IP blacklists; if domain(s) provided, resolve A/AAAA and query those IPs
            // -TreatAsDomain: always domain + MX-IP path
            // default: domains => domain+MX-IP, IPs => IP blacklists; mixed arrays aggregate results
            healthCheck.DNSBLAnalysis.Reset();
            bool first = true;
            var scanMode = DomainIpScan ?? DomainIpScanMode.MxThenApexFallback;

            if (TreatAsIp) {
                var ips = new System.Collections.Generic.List<string>();
                foreach (var input in NameOrIpAddress) {
                    if (System.Net.IPAddress.TryParse(input, out _)) {
                        ips.Add(input);
                    } else {
                        // Resolve A/AAAA for domain and add those IPs
                        var a = await healthCheck.DnsConfiguration.QueryDNS(input, DnsClientX.DnsRecordType.A);
                        foreach (var ans in a) ips.Add(ans.Data);
                        var aaaa = await healthCheck.DnsConfiguration.QueryDNS(input, DnsClientX.DnsRecordType.AAAA);
                        foreach (var ans in aaaa) ips.Add(ans.Data);
                    }
                }
                if (ips.Count > 0) {
                    await healthCheck.DNSBLAnalysis.AnalyzeDNSBLRecordsMany(ips, _logger, clearExisting: true);
                    first = false;
                }
            } else {
                // Default/TreatAsDomain for domains
                foreach (var input in NameOrIpAddress) {
                    var isIp = System.Net.IPAddress.TryParse(input, out _);
                    if (isIp && !TreatAsDomain) {
                        await healthCheck.DNSBLAnalysis.AnalyzeDNSBLRecordsMany(new[] { input }, _logger, clearExisting: first);
                        first = false;
                    } else {
                        var clear = first;
                        first = false;
                        await healthCheck.VerifyDNSBLWithMode(input, scanMode, clearExisting: clear);
                    }
                }
            }

            if (NameOrIpAddress.Length == 1) {
                var input = NameOrIpAddress[0];
                var isIp = System.Net.IPAddress.TryParse(input, out _);

                if (FullResponse) {
                    // For domains, return full dictionary (domain + MX-IP) to give complete context
                    if (isIp) {
                        if (!healthCheck.DNSBLAnalysis.Results.TryGetValue(input, out var res)) {
                            WriteObject(System.Array.Empty<object>());
                            goto AfterWrite;
                        }
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
                    // Default simplified summary view
                    var view = DomainDetective.Views.Converters.Convert(healthCheck.DNSBLAnalysis);
                    WriteObject(view);
                    goto AfterWrite;
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
                    var view = DomainDetective.Views.Converters.Convert(healthCheck.DNSBLAnalysis);
                    WriteObject(view);
                }
            }
AfterWrite:
            if (IsExportRequested()) {
                try {
                    var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                    if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                        var view = DomainDetective.Views.Converters.Convert(healthCheck.DNSBLAnalysis);
                        // Ensure a non-empty Subject for grouping when inputs are IP-only
                        if (string.IsNullOrWhiteSpace(view.Subject)) {
                            var firstKey = healthCheck.DNSBLAnalysis.Results.Keys.FirstOrDefault();
                            view.Subject = string.IsNullOrWhiteSpace(firstKey) ? "DNSBL" : firstKey;
                        }
                        var items = new System.Collections.Generic.List<object> { view };
                        var label = view.Subject ?? "DNSBL";
                        var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, fmt);
                        if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                            DomainDetective.Reports.Office.WordCompositionReport.Generate(
                                outPath,
                                items,
                                DomainDetective.Reports.ReportScope.Normal,
                                showInfoFindings: true,
                                narrativePlacement: ExportDefaults.NarrativePlacement,
                                titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"DNSBL Report — {label}" : ExportDefaults.NarrativeTitle,
                                subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                                categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                                keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                                creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator);
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                        } else {
                            DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                                outPath,
                                items,
                                DomainDetective.Reports.ReportScope.Normal,
                                OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                                ExportDefaults.NarrativePlacement,
                                titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle,
                                authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                                descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);
                        }
                    } else {
                        await ExportNotImplementedAsync();
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"DNSBL export failed: {ex.Message}");
                }
                return;
            }
        }
    }
}
