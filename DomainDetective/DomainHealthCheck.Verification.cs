using DnsClientX;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.Reflection;
using System.Linq.Expressions;
using System.Globalization;
using DomainDetective.Network;
using DomainDetective.Helpers;

using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
namespace DomainDetective {
    /// <summary>
    /// Contains verification methods used by <see cref="DomainHealthCheck"/>.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public partial class DomainHealthCheck {

        private static string NormalizeDomain(string input)
        {
            if (IPAddress.TryParse(input, out _)) {
                return input.ToLowerInvariant();
            }
            return DomainHelper.ValidateIdn(input).ToLowerInvariant();
        }

        private static string CreateServiceQuery(int port, string domain) {
#if NET6_0_OR_GREATER
            var portString = port.ToString(CultureInfo.InvariantCulture);
            return string.Create(portString.Length + domain.Length + 7, (portString, domain), static (span, state) => {
                var (digits, host) = state;
                var pos = 0;
                span[pos++] = '_';
                digits.AsSpan().CopyTo(span[pos..]);
                pos += digits.Length;
                "._tcp.".AsSpan().CopyTo(span[pos..]);
                pos += 6;
                host.AsSpan().CopyTo(span[pos..]);
            });
#else
            return $"_{port}._tcp.{domain}";
#endif
        }

        private static void ValidateServiceQueryProtocol(string query) {
            bool hasTcp = query.IndexOf("._tcp.", StringComparison.OrdinalIgnoreCase) >= 0;
            bool hasUdp = query.IndexOf("._udp.", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!hasTcp && !hasUdp) {
                throw new InvalidOperationException($"Invalid service query '{query}', expected _tcp or _udp suffix.");
            }
        }

        private void UpdateIsPublicSuffix(string domainName) {
            string host = domainName;
            if (Uri.TryCreate($"http://{domainName}", UriKind.Absolute, out var uri)) {
                host = uri.Host;
            } else {
                try {
                    host = DomainHelper.ValidateIdn(domainName);
                } catch (ArgumentException) {
                }
            }

            if (IPAddress.TryParse(host, out _)) {
                IsPublicSuffix = false;
                return;
            }

            var ascii = NormalizeDomain(host);
            IsPublicSuffix = _publicSuffixList.IsPublicSuffix(ascii);
        }

        /// <summary>
        /// Runs the requested health checks against a domain.
        /// </summary>
        /// <param name="domainName">Domain to validate.</param>
        /// <param name="healthCheckTypes">Health checks to execute or <c>null</c> for defaults.</param>
        /// <param name="dkimSelectors">DKIM selectors to use when verifying DKIM.</param>
        /// <param name="daneServiceType">DANE service types to inspect. When <c>null</c>, SMTP and HTTPS (port 443) are queried.</param>
        /// <param name="danePorts">Custom ports to check for DANE. Overrides <paramref name="daneServiceType"/> when provided.</param>
        /// <param name="portScanProfiles">Optional port scan profiles to use.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        /// <param name="executionOptions">Optional execution settings for this verification run.</param>
        public async Task Verify(
            string domainName,
            HealthCheckType[]? healthCheckTypes = null,
            string[]? dkimSelectors = null,
            ServiceType[]? daneServiceType = null,
            int[]? danePorts = null,
            PortScanProfile[]? portScanProfiles = null,
            CancellationToken cancellationToken = default,
            HealthCheckExecutionOptions? executionOptions = null) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            ResetExecutionState();
            IsPublicSuffix = false;
            domainName = ValidateHostName(domainName);
            UpdateIsPublicSuffix(domainName);
            var exec = executionOptions ?? ExecutionOptions;
            if (exec.ResetLogDedupOnRun) {
                _logger.ClearLoggedMessages();
            }
            ApplyExecutionOptions(exec);
            _logger.WriteVerbose("Running health checks for {0}", domainName);
            if (healthCheckTypes == null || healthCheckTypes.Length == 0) {     
                healthCheckTypes = new[]                {
                    HealthCheckType.DMARC,
                    HealthCheckType.SPF,
                    HealthCheckType.DKIM,
                    HealthCheckType.MX,
                    HealthCheckType.CAA,
                    HealthCheckType.DANE,
                    HealthCheckType.DNSSEC,
                    HealthCheckType.DNSBL,
                    HealthCheckType.MESSAGEHEADER
                };
            }

            healthCheckTypes = healthCheckTypes.Distinct().ToArray();

            var totalChecks = healthCheckTypes.Length;
            var processedChecks = 0;

            var actions = new Dictionary<HealthCheckType, Func<Task>> {
                [HealthCheckType.DMARC] = () => VerifyDMARC(domainName, cancellationToken),
                [HealthCheckType.SPF] = () => VerifySPF(domainName, cancellationToken),
                [HealthCheckType.DKIM] = () => VerifyDKIM(domainName, dkimSelectors ?? Definitions.DKIMSelectors.GuessSelectors().ToArray(), cancellationToken),
                [HealthCheckType.MX] = () => VerifyMX(domainName, cancellationToken),
                [HealthCheckType.REVERSEDNS] = () => VerifyReverseDnsAsync(domainName, cancellationToken),
                [HealthCheckType.FCRDNS] = () => VerifyFcrDnsAsync(domainName, cancellationToken),
                [HealthCheckType.CAA] = () => VerifyCAA(domainName, cancellationToken),
                [HealthCheckType.NS] = () => VerifyNS(domainName, cancellationToken),
                [HealthCheckType.DELEGATION] = () => VerifyDelegation(domainName, cancellationToken),
                [HealthCheckType.ZONETRANSFER] = () => VerifyZoneTransfer(domainName, cancellationToken),
                [HealthCheckType.DANE] = () => VerifyDaneAsync(domainName, daneServiceType, danePorts, cancellationToken),
                [HealthCheckType.DNSSEC] = () => VerifyDNSSEC(domainName, cancellationToken),
                [HealthCheckType.DNSBL] = () => VerifyDNSBL(domainName, cancellationToken),
                [HealthCheckType.MTASTS] = () => VerifyMTASTS(domainName, cancellationToken),
                [HealthCheckType.TLSRPT] = () => VerifyTLSRPT(domainName, cancellationToken),
                [HealthCheckType.BIMI] = () => VerifyBIMI(domainName, cancellationToken: cancellationToken),
                [HealthCheckType.AUTODISCOVER] = () => VerifyAutodiscover(domainName, cancellationToken),
                [HealthCheckType.CERT] = () => VerifyWebsiteCertificate(domainName, cancellationToken: cancellationToken),
                [HealthCheckType.SECURITYTXT] = () => VerifySecurityTxtAsync(domainName, cancellationToken),
                [HealthCheckType.ROBOTS] = () => VerifyRobotsAsync(domainName, cancellationToken),
                [HealthCheckType.SOA] = () => VerifySOA(domainName, cancellationToken),
                [HealthCheckType.OPENRELAY] = () => VerifyOpenRelay(domainName, 25, cancellationToken),
                [HealthCheckType.OPENRESOLVER] = () => VerifyOpenResolver(domainName, cancellationToken),
                [HealthCheckType.STARTTLS] = () => VerifySTARTTLS(domainName, 25, cancellationToken),
                [HealthCheckType.SMTPTLS] = () => VerifySMTPTLS(domainName, 25, cancellationToken),
                [HealthCheckType.IMAPTLS] = () => VerifyIMAPTLS(domainName, cancellationToken),
                [HealthCheckType.POP3TLS] = () => VerifyPOP3TLS(domainName, cancellationToken),
                [HealthCheckType.SMTPBANNER] = () => VerifySMTPBanner(domainName, 25, cancellationToken),
                [HealthCheckType.SMTPAUTH] = () => VerifySmtpAuth(domainName, 25, cancellationToken),
                [HealthCheckType.HTTP] = () => VerifyPlainHttp(domainName, cancellationToken),
                [HealthCheckType.HPKP] = () => VerifyHpkpAsync(domainName, cancellationToken),
                [HealthCheckType.CONTACT] = () => VerifyContactInfo(domainName, cancellationToken),
                [HealthCheckType.MESSAGEHEADER] = () => VerifyMessageHeaderAsync(cancellationToken),
                [HealthCheckType.DANGLINGCNAME] = () => VerifyDanglingCname(domainName, cancellationToken),
                [HealthCheckType.TTL] = () => VerifyDnsTtlAsync(domainName, cancellationToken),
                [HealthCheckType.PORTAVAILABILITY] = () => CheckPortAvailability(domainName, null, cancellationToken),
                [HealthCheckType.PORTSCAN] = () => ScanPorts(domainName, null, portScanProfiles, cancellationToken),
                [HealthCheckType.SNMP] = () => CheckSnmpHost(domainName, 161, cancellationToken),
                [HealthCheckType.IPNEIGHBOR] = () => CheckIPNeighbors(domainName, cancellationToken),
                [HealthCheckType.RPKI] = () => VerifyRPKI(domainName, cancellationToken),
                [HealthCheckType.RDAP] = () => QueryRDAP(domainName, cancellationToken),
                [HealthCheckType.DNSTUNNELING] = () => CheckDnsTunnelingAsync(domainName, cancellationToken),
                [HealthCheckType.TYPOSQUATTING] = () => VerifyTyposquatting(domainName, cancellationToken),
                [HealthCheckType.WILDCARDDNS] = () => VerifyWildcardDns(domainName),
                [HealthCheckType.EDNSSUPPORT] = () => VerifyEdnsSupport(domainName, cancellationToken),
                [HealthCheckType.DNSHEALTH] = () => VerifyDnsHealth(domainName, cancellationToken),
                [HealthCheckType.FLATTENINGSERVICE] = () => VerifyFlatteningServiceAsync(domainName, cancellationToken),
                [HealthCheckType.THREATINTEL] = () => VerifyThreatIntel(domainName, cancellationToken),
                [HealthCheckType.THREATFEED] = () => VerifyThreatFeed(domainName, cancellationToken),
                [HealthCheckType.DIRECTORYEXPOSURE] = () => VerifyDirectoryExposure(domainName, cancellationToken)
            };

            if (healthCheckTypes.Contains(HealthCheckType.DANE)) {
                var daneTask = new Lazy<Task>(() => EnsureDaneAsync(domainName, daneServiceType, danePorts, cancellationToken));
                actions[HealthCheckType.DANE] = () => daneTask.Value;
                if (!exec.EnableParallelism && actions.TryGetValue(HealthCheckType.SMTPTLS, out var smtpAction)) {
                    actions[HealthCheckType.SMTPTLS] = async () => {
                        await daneTask.Value;
                        await smtpAction();
                    };
                }
                if (exec.EnableParallelism && (healthCheckTypes.Contains(HealthCheckType.SMTPTLS) || healthCheckTypes.Contains(HealthCheckType.MTASTS))) {
                    _ = daneTask.Value;
                }
            }

            void ReportProgress(string operation, int completed) {
                if (totalChecks <= 0) {
                    return;
                }
                _logger.WriteProgress(
                    "HealthCheck",
                    operation,
                    completed * 100d / totalChecks,
                    completed,
                    totalChecks);
            }

            async Task RunCheckAsync(HealthCheckType healthCheckType) {
                cancellationToken.ThrowIfCancellationRequested();
                var sw = Stopwatch.StartNew();
                _logger.WriteVerbose("Starting {0} check.", healthCheckType);
                if (actions.TryGetValue(healthCheckType, out var action)) {
                    await action();
                } else {
                    _logger.WriteError("Unknown health check type: {0}", healthCheckType);
                    throw new NotSupportedException($"Health check type not implemented: {(int)healthCheckType}");
                }
                sw.Stop();
                _logger.WriteVerbose("{0} check completed in {1} ms.", healthCheckType, sw.ElapsedMilliseconds);
            }

            async Task RunCheckWithGateAsync(HealthCheckType healthCheckType, SemaphoreSlim gate) {
                await gate.WaitAsync(cancellationToken);
                try {
                    await RunCheckAsync(healthCheckType);
                } finally {
                    gate.Release();
                }
                var done = Interlocked.Increment(ref processedChecks);
                _logger.WriteInformation("{0} check completed", healthCheckType);
                ReportProgress(healthCheckType.ToString(), done);
            }

            if (!exec.EnableParallelism || totalChecks <= 1) {
                _logger.WriteVerbose("Parallel execution disabled; running checks sequentially.");
                foreach (var healthCheckType in healthCheckTypes) {
                    ReportProgress(healthCheckType.ToString(), processedChecks);
                    await RunCheckAsync(healthCheckType);
                    processedChecks++;
                    _logger.WriteInformation("{0} check completed", healthCheckType);
                    ReportProgress(healthCheckType.ToString(), processedChecks);
                }
            } else {
                var maxParallelism = exec.GetEffectiveMaxParallelism();
                _logger.WriteVerbose("Parallel execution enabled: max {0} concurrent checks.", maxParallelism);
                ReportProgress("Starting", 0);
                using var gate = new SemaphoreSlim(maxParallelism, maxParallelism);
                var tasks = new List<Task>(healthCheckTypes.Length);
                foreach (var healthCheckType in healthCheckTypes) {
                    tasks.Add(RunCheckWithGateAsync(healthCheckType, gate));
                }
                await Task.WhenAll(tasks);
            }

            // Compute provider inference once core mail checks ran (best-effort; safe if some were skipped)
            try { ComputeEmailProviderMatch(); } catch { /* non-fatal */ }
    }

        private void ApplyExecutionOptions(HealthCheckExecutionOptions options) {
            var effectiveMax = options.GetEffectiveMaxParallelism();
            var effectiveDns = options.GetEffectiveDnsParallelism();

            if (options.DnsParallelism.HasValue) {
                if (DnsConfiguration.SupportsResolverConcurrency) {
                    ResolverMaxConcurrency = options.DnsParallelism.Value;
                }
                if (!MultiResolverMaxParallelism.HasValue) {
                    MultiResolverMaxParallelism = options.DnsParallelism.Value;
                }
            } else {
                if (DnsConfiguration.SupportsResolverConcurrency && !ResolverMaxConcurrency.HasValue) {
                    ResolverMaxConcurrency = effectiveDns;
                }
                if (!MultiResolverMaxParallelism.HasValue) {
                    MultiResolverMaxParallelism = effectiveDns;
                }
            }

            _logger.WriteVerbose(
                "Execution options: Parallel={0}, MaxParallelism={1}, DnsParallelism={2}, SharedMxCache={3}",
                options.EnableParallelism,
                effectiveMax,
                effectiveDns,
                options.EnableSharedMxCache);
        }

        private async Task VerifyDnsHealth(string domainName, CancellationToken cancellationToken) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            DnsHealthAnalysis.Subject = domainName;
            await DnsHealthAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// <summary>Creates a high level summary of key analyses.</summary>
        /// <returns>A populated <see cref="DomainSummary"/>.</returns>
        public DomainSummary BuildSummary() {
            var spfValid = SpfAnalysis.SpfRecordExists && SpfAnalysis.StartsCorrectly &&
                            !SpfAnalysis.ExceedsDnsLookups && !SpfAnalysis.MultipleSpfRecords;

            var dmarcValid = DmarcAnalysis.DmarcRecordExists && DmarcAnalysis.StartsCorrectly &&
                             DmarcAnalysis.HasMandatoryTags && DmarcAnalysis.IsPolicyValid &&
                             DmarcAnalysis.IsPctValid && !DmarcAnalysis.MultipleRecords &&
                             !DmarcAnalysis.ExceedsCharacterLimit && DmarcAnalysis.ValidDkimAlignment &&
                             DmarcAnalysis.ValidSpfAlignment;

            var dkimValid = DKIMAnalysis.AnalysisResults.Values.Any(a =>
                a.DkimRecordExists && a.StartsCorrectly && a.PublicKeyExists &&
                a.ValidPublicKey && a.KeyTypeExists && a.ValidKeyType && a.ValidFlags);

            var hints = new List<string>();

            static void AddHint(List<string> list, HealthCheckType type) {
                var hint = CheckDescriptions.Get(type)?.Remediation;
                if (!string.IsNullOrWhiteSpace(hint)) {
                    list.Add(hint!);
                }
            }

            if (!spfValid) {
                AddHint(hints, HealthCheckType.SPF);
            }
            if (!dmarcValid) {
                AddHint(hints, HealthCheckType.DMARC);
            }
            if (!dkimValid) {
                AddHint(hints, HealthCheckType.DKIM);
            }
            if (MXAnalysis is { MxRecordExists: false }) {
                AddHint(hints, HealthCheckType.MX);
            }
            if (!(DnsSecAnalysis?.ChainValid ?? false)) {
                AddHint(hints, HealthCheckType.DNSSEC);
            }
            if (WhoisAnalysis.IsExpired || WhoisAnalysis.ExpiresSoon) {
                hints.Add("Renew the domain registration.");
            }

            return new DomainSummary {
                HasSpfRecord = SpfAnalysis.SpfRecordExists,
                SpfValid = spfValid,
                HasDmarcRecord = DmarcAnalysis.DmarcRecordExists,
                DmarcPolicy = DmarcAnalysis.Policy,
                DmarcValid = dmarcValid,
                HasDkimRecord = DKIMAnalysis.AnalysisResults.Values.Any(a => a.DkimRecordExists),
                DkimValid = dkimValid,
                HasMxRecord = MXAnalysis?.MxRecordExists ?? false,
                DnsSecValid = DnsSecAnalysis?.ChainValid ?? false,
                DnsSecKeyExpiresSoon = DnsSecAnalysis?.KeyExpiresSoon ?? false,
                IsPublicSuffix = IsPublicSuffix,
                ExpiryDate = WhoisAnalysis.ExpiryDate ?? string.Empty,
                DaysUntilExpiration = WhoisAnalysis.DaysUntilExpiration,
                ExpiresSoon = WhoisAnalysis.ExpiresSoon,
                IsExpired = WhoisAnalysis.IsExpired,
                RegistrarLocked = WhoisAnalysis.RegistrarLocked,
                PrivacyProtected = WhoisAnalysis.PrivacyProtected,
                Hints = hints.ToArray()
            };
        }

        /// <summary>
        /// Quick access to a condensed summary of this health check.
        /// </summary>
        public DomainSummary Summary => BuildSummary();

        /// <summary>Serializes this instance to a JSON string.</summary>
        /// <param name="options">
        /// <para>Optional serializer options. If not provided,</para>
        /// <para><see cref="JsonSerializerOptions.WriteIndented"/> is enabled.</para>
        /// </param>
        /// <returns>
        /// <para>A JSON representation of the current
        /// <see cref="DomainHealthCheck"/>.</para>
        /// </returns>
        public string ToJson(JsonSerializerOptions? options = null) {
            options ??= JsonOptions;
            if (UnicodeOutput && options.Converters.All(c => c is not IdnStringConverter)) {
                var local = new JsonSerializerOptions(options);
                local.Converters.Add(new IdnStringConverter(true));
                return JsonSerializer.Serialize(this, local);
            }
            return JsonSerializer.Serialize(this, options);
        }

        private static void ValidatePort(int port) {
            if (port <= 0 || port > 65535) {
                throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535.");
            }
        }

        private static string ValidateHostName(string domainName) {
            var trimmed = domainName?.Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            var trimmedValue = trimmed!;

            if (!Uri.TryCreate($"http://{trimmedValue}", UriKind.Absolute, out var uri)) {
                // older frameworks may not handle IDN automatically
                var hostName = trimmedValue;
                var portIndex = trimmedValue.LastIndexOf(':');
                if (portIndex > 0 && trimmedValue.IndexOf(':') == portIndex &&
                    int.TryParse(trimmedValue.Substring(portIndex + 1), out _)) {
                    hostName = trimmedValue.Substring(0, portIndex);
                }

                try {
                    hostName = DomainHelper.ValidateIdn(hostName);
                } catch (ArgumentException) {
                    throw new ArgumentException($"Invalid host name '{trimmedValue}'.", nameof(domainName));
                }

                var rebuilt = portIndex > 0 && trimmedValue.IndexOf(':') == portIndex
                    ? hostName + trimmedValue.Substring(portIndex)
                    : hostName;

                if (!Uri.TryCreate($"http://{rebuilt}", UriKind.Absolute, out uri)) {
                    throw new ArgumentException($"Invalid host name '{trimmedValue}'.", nameof(domainName));
                }
            }

            if (!string.IsNullOrEmpty(uri.PathAndQuery) && uri.PathAndQuery != "/" ||
                !string.IsNullOrEmpty(uri.Fragment)) {
                throw new ArgumentException($"Invalid host name '{trimmed}'.", nameof(domainName));
            }

            var host = uri.IdnHost;
            if (uri.HostNameType == UriHostNameType.Dns) {
                var labels = host.Split('.');
                if (labels.Length == 0 ||
                    !Helpers.DomainHelper.IsValidTld(labels[labels.Length - 1])) {
                    throw new ArgumentException(
                        $"Invalid host name '{trimmed}'.",
                        nameof(domainName));
                }
            }

            if (!uri.IsDefaultPort) {
                if (uri.Port <= 0 || uri.Port > 65535) {
                    throw new ArgumentException($"Invalid port '{uri.Port}'.", nameof(domainName));
                }
                if (uri.HostNameType == UriHostNameType.Dns) {
                    return $"{NormalizeDomain(host)}:{uri.Port}";
                }
                return $"{host}:{uri.Port}";
            }

            if (uri.HostNameType == UriHostNameType.Dns) {
                return NormalizeDomain(host);
            }

            return host;
        }

        /// <summary>Creates a copy with only the specified analyses included.</summary>
        /// <param name="healthCheckTypes">
        /// <para>Health checks that should remain in the returned
        /// <see cref="DomainHealthCheck"/>.</para>
        /// </param>
        /// <returns>
        /// <para>A clone of this object with non-selected analyses removed.</para>
        /// </returns>
        public DomainHealthCheck FilterAnalyses(IEnumerable<HealthCheckType> healthCheckTypes) {
            var active = healthCheckTypes != null
                ? new HashSet<HealthCheckType>(healthCheckTypes)
                : new HashSet<HealthCheckType>();

            var filtered = new DomainHealthCheck(DnsEndpoint, _logger) {
                DnsSelectionStrategy = DnsSelectionStrategy,
                DnsConfiguration = DnsConfiguration,
                MtaStsPolicyUrlOverride = MtaStsPolicyUrlOverride
            };

            filtered.DmarcAnalysis = active.Contains(HealthCheckType.DMARC) ? CloneAnalysis(DmarcAnalysis) : null!;
            filtered.SpfAnalysis = active.Contains(HealthCheckType.SPF) ? CloneAnalysis(SpfAnalysis) : null!;
            filtered.DKIMAnalysis = active.Contains(HealthCheckType.DKIM) ? CloneAnalysis(DKIMAnalysis) : null!;
            filtered.MXAnalysis = active.Contains(HealthCheckType.MX) ? CloneAnalysis(MXAnalysis) : null!;
            filtered.ReverseDnsAnalysis = active.Contains(HealthCheckType.REVERSEDNS) ? CloneAnalysis(ReverseDnsAnalysis) : null!;
            filtered.FcrDnsAnalysis = active.Contains(HealthCheckType.FCRDNS) ? CloneAnalysis(FcrDnsAnalysis) : null!;
            filtered.CAAAnalysis = active.Contains(HealthCheckType.CAA) ? CloneAnalysis(CAAAnalysis) : null!;
            filtered.NSAnalysis =
                active.Contains(HealthCheckType.NS) || active.Contains(HealthCheckType.DELEGATION)
                    ? CloneAnalysis(NSAnalysis)
                    : null!;
            filtered.ZoneTransferAnalysis = active.Contains(HealthCheckType.ZONETRANSFER) ? CloneAnalysis(ZoneTransferAnalysis) : null!;
            filtered.DaneAnalysis = active.Contains(HealthCheckType.DANE) ? CloneAnalysis(DaneAnalysis) : null!;
            filtered.DNSBLAnalysis = active.Contains(HealthCheckType.DNSBL) ? CloneAnalysis(DNSBLAnalysis) : null!;
            filtered.DnsSecAnalysis = active.Contains(HealthCheckType.DNSSEC) ? CloneAnalysis(DnsSecAnalysis) : null!;
            filtered.MTASTSAnalysis = active.Contains(HealthCheckType.MTASTS) ? CloneAnalysis(MTASTSAnalysis) : null!;
            filtered.TLSRPTAnalysis = active.Contains(HealthCheckType.TLSRPT) ? CloneAnalysis(TLSRPTAnalysis) : null!;
            filtered.BimiAnalysis = active.Contains(HealthCheckType.BIMI) ? CloneAnalysis(BimiAnalysis) : null!;
            filtered.AutodiscoverAnalysis = active.Contains(HealthCheckType.AUTODISCOVER) ? CloneAnalysis(AutodiscoverAnalysis) : null!;
            filtered.AutodiscoverHttpAnalysis = active.Contains(HealthCheckType.AUTODISCOVER) ? CloneAnalysis(AutodiscoverHttpAnalysis) : null!;
            filtered.CertificateAnalysis = active.Contains(HealthCheckType.CERT) ? CloneAnalysis(CertificateAnalysis) : null!;
            filtered.SecurityTXTAnalysis = active.Contains(HealthCheckType.SECURITYTXT) ? CloneAnalysis(SecurityTXTAnalysis) : null!;
            filtered.SOAAnalysis = active.Contains(HealthCheckType.SOA) ? CloneAnalysis(SOAAnalysis) : null!;
            filtered.OpenRelayAnalysis = active.Contains(HealthCheckType.OPENRELAY) ? CloneAnalysis(OpenRelayAnalysis) : null!;
            filtered.OpenResolverAnalysis = active.Contains(HealthCheckType.OPENRESOLVER) ? CloneAnalysis(OpenResolverAnalysis) : null!;
            filtered.StartTlsAnalysis = active.Contains(HealthCheckType.STARTTLS) ? CloneAnalysis(StartTlsAnalysis) : null!;
            filtered.SmtpTlsAnalysis = active.Contains(HealthCheckType.SMTPTLS) ? CloneAnalysis(SmtpTlsAnalysis) : null!;
            filtered.ImapTlsAnalysis = active.Contains(HealthCheckType.IMAPTLS) ? CloneAnalysis(ImapTlsAnalysis) : null!;
            filtered.Pop3TlsAnalysis = active.Contains(HealthCheckType.POP3TLS) ? CloneAnalysis(Pop3TlsAnalysis) : null!;
            filtered.SmtpBannerAnalysis = active.Contains(HealthCheckType.SMTPBANNER) ? CloneAnalysis(SmtpBannerAnalysis) : null!;
            filtered.SmtpAuthAnalysis = active.Contains(HealthCheckType.SMTPAUTH) ? CloneAnalysis(SmtpAuthAnalysis) : null!;
            filtered.HttpAnalysis = active.Contains(HealthCheckType.HTTP) ? CloneAnalysis(HttpAnalysis) : null!;
            filtered.HPKPAnalysis = active.Contains(HealthCheckType.HPKP) ? CloneAnalysis(HPKPAnalysis) : null!;
            filtered.ContactInfoAnalysis = active.Contains(HealthCheckType.CONTACT) ? CloneAnalysis(ContactInfoAnalysis) : null!;
            filtered.MessageHeaderAnalysis = active.Contains(HealthCheckType.MESSAGEHEADER) ? CloneAnalysis(MessageHeaderAnalysis) : null!;
            filtered.ArcAnalysis = active.Contains(HealthCheckType.ARC) ? CloneAnalysis(ArcAnalysis) : null!;
            filtered.DanglingCnameAnalysis = active.Contains(HealthCheckType.DANGLINGCNAME) ? CloneAnalysis(DanglingCnameAnalysis) : null!;
            filtered.DnsTtlAnalysis = active.Contains(HealthCheckType.TTL) ? CloneAnalysis(DnsTtlAnalysis) : null!;
            filtered.PortAvailabilityAnalysis = active.Contains(HealthCheckType.PORTAVAILABILITY) ? CloneAnalysis(PortAvailabilityAnalysis) : null!;
            filtered.PortScanAnalysis = active.Contains(HealthCheckType.PORTSCAN) ? CloneAnalysis(PortScanAnalysis) : null!;
            filtered.SnmpAnalysis = active.Contains(HealthCheckType.SNMP) ? CloneAnalysis(SnmpAnalysis) : null!;
            filtered.IPNeighborAnalysis = active.Contains(HealthCheckType.IPNEIGHBOR) ? CloneAnalysis(IPNeighborAnalysis) : null!;
            filtered.DnsTunnelingAnalysis = active.Contains(HealthCheckType.DNSTUNNELING) ? CloneAnalysis(DnsTunnelingAnalysis) : null!;
            filtered.TyposquattingAnalysis = active.Contains(HealthCheckType.TYPOSQUATTING) ? CloneAnalysis(TyposquattingAnalysis) : null!;
            filtered.ThreatIntelAnalysis = active.Contains(HealthCheckType.THREATINTEL) ? CloneAnalysis(ThreatIntelAnalysis) : null!;
            filtered.ThreatFeedAnalysis = active.Contains(HealthCheckType.THREATFEED) ? CloneAnalysis(ThreatFeedAnalysis) : null!;
            filtered.WildcardDnsAnalysis = active.Contains(HealthCheckType.WILDCARDDNS) ? CloneAnalysis(WildcardDnsAnalysis) : null!;
            filtered.EdnsSupportAnalysis = active.Contains(HealthCheckType.EDNSSUPPORT) ? CloneAnalysis(EdnsSupportAnalysis) : null!;
            filtered.FlatteningServiceAnalysis = active.Contains(HealthCheckType.FLATTENINGSERVICE) ? CloneAnalysis(FlatteningServiceAnalysis) : null!;
            filtered.DirectoryExposureAnalysis = active.Contains(HealthCheckType.DIRECTORYEXPOSURE) ? CloneAnalysis(DirectoryExposureAnalysis) : null!;
            filtered.NtpAnalysis = active.Contains(HealthCheckType.NTP) ? CloneAnalysis(NtpAnalysis) : null!;

            return filtered;
        }

        private static readonly MethodInfo _cloneMethod = typeof(object).GetMethod(
                "MemberwiseClone",
                BindingFlags.Instance | BindingFlags.NonPublic) ??
            throw new InvalidOperationException("Unable to locate MemberwiseClone method.");

        private static class Cloner<T> where T : class {
            internal static readonly Func<T, T> Delegate = CreateDelegate();

            private static Func<T, T> CreateDelegate() {
                ParameterExpression param = Expression.Parameter(typeof(T), "source");
                UnaryExpression body = Expression.Convert(Expression.Call(param, _cloneMethod), typeof(T));
                return Expression.Lambda<Func<T, T>>(body, param).Compile();
            }
        }

        private static T CloneAnalysis<T>(T analysis) where T : class {
            return analysis == null ? null! : Cloner<T>.Delegate(analysis);
        }
    }
}
