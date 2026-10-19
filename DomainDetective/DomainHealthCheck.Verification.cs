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
using DomainDetective.Network;
using DomainDetective.Helpers;

using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
namespace DomainDetective {
    /// <summary>
    /// Contains verification methods used by <see cref="DomainHealthCheck"/>.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
public partial class DomainHealthCheck {
        /// <summary>Represents the default checks value.</summary>
        public static readonly HealthCheckType[] DefaultChecks = new[] {
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

        private static string NormalizeDomain(string input)
        {
            if (IPAddress.TryParse(input, out _)) {
                return input.ToLowerInvariant();
            }
            return DomainHelper.ValidateIdn(input).ToLowerInvariant();
        }

        private static string CreateServiceQuery(int port, string domain) {
            return $"_{port}._tcp.{domain}";
        }

        /// <summary>
        /// Determines whether a health check can run from a domain or host input alone.
        /// </summary>
        /// <param name="healthCheckType">Health check to evaluate.</param>
        /// <returns><c>true</c> when <see cref="Verify"/> can execute the check directly.</returns>
        public static bool SupportsDomainVerification(HealthCheckType healthCheckType) {
            switch (healthCheckType) {
                case HealthCheckType.ARC:
                case HealthCheckType.SMIMEA:
                    return false;
                default:
                    return true;
            }
        }

        private static void ValidateDomainVerificationTypes(IEnumerable<HealthCheckType> healthCheckTypes) {
            var unsupported = healthCheckTypes
                .Where(type => !SupportsDomainVerification(type))
                .Distinct()
                .ToArray();
            if (unsupported.Length == 0) {
                return;
            }

            throw new ArgumentException(
                $"The following health checks require specialized input and cannot be executed via Verify(domain): {string.Join(", ", unsupported)}.",
                nameof(healthCheckTypes));
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
        /// <param name="useDefaultChecksWhenEmpty">When false, an empty <paramref name="healthCheckTypes"/> array results in no checks being executed.</param>
        public async Task Verify(
            string domainName,
            HealthCheckType[]? healthCheckTypes = null,
            string[]? dkimSelectors = null,
            ServiceType[]? daneServiceType = null,
            int[]? danePorts = null,
            PortScanProfile[]? portScanProfiles = null,
            CancellationToken cancellationToken = default,
            HealthCheckExecutionOptions? executionOptions = null,
            bool useDefaultChecksWhenEmpty = true) {
            await _verificationAdmission.WaitAsync(cancellationToken).ConfigureAwait(false);
            _ownsVerification.Value = true;
            try {
                VerificationCompleted = false;
                VerificationError = null;
                VerificationPlainHttpCompleted = null;
                VerificationTakeoverCompleted = null;
                VerificationRequestedChecks = Array.Empty<HealthCheckType>();
                _completedVerificationChecks.Clear();
                var configuration = DnsConfiguration;
                var previousAdmission = configuration.QueryAdmissionGate;
                var previousBulkAdmission = configuration.BulkQueryAdmissionGate;
                var previousResolverBulkAdmission = configuration.ResolverBulkQueryAdmissionGate;
                int dnsParallelism = (executionOptions ?? ExecutionOptions).GetEffectiveDnsParallelism();
                using var observations = new ScanObservations((executionOptions ?? ExecutionOptions).DnsParallelism);
                // Async-only gates allocate no wait handle. A public configuration query may
                // outlive Verify after borrowing this gate, so let its last borrower release it to GC.
                var ownedAdmission = previousAdmission == null
                    ? new SemaphoreSlim(dnsParallelism) : null;
                var resolverBulkAdmission = previousResolverBulkAdmission
                    ?? new SemaphoreSlim(Math.Max(1, configuration.GetBulkQueryParallelism(dnsParallelism)));
                configuration.QueryAdmissionGate = previousAdmission ?? ownedAdmission;
                configuration.BulkQueryAdmissionGate = previousBulkAdmission ?? new SemaphoreSlim(Math.Max(1, dnsParallelism - 1));
                configuration.ResolverBulkQueryAdmissionGate = resolverBulkAdmission;
                try {
                    await VerifyCore(domainName, healthCheckTypes, dkimSelectors, daneServiceType, danePorts,
                        portScanProfiles, cancellationToken, executionOptions, useDefaultChecksWhenEmpty).ConfigureAwait(false);
                    ThrowRecordedCheckFailure();
                } finally {
                    _runOperations = null;
                    _runCheckAdmission = null;
                    _runDomain = null;
                    _selectedRunChecks = null;
                    _runNeedsSmtpDane = false;
                    configuration.QueryAdmissionGate = previousAdmission;
                    configuration.BulkQueryAdmissionGate = previousBulkAdmission;
                    configuration.ResolverBulkQueryAdmissionGate = previousResolverBulkAdmission;
                }
                VerificationCompleted = true;
            } catch (Exception exception) {
                VerificationCompleted = false;
                if (cancellationToken.IsCancellationRequested && exception is not OutOfMemoryException) {
                    var canceled = new OperationCanceledException(cancellationToken);
                    VerificationError = canceled.Message;
                    throw canceled;
                }
                VerificationError = exception.Message;
                throw;
            } finally { _ownsVerification.Value = false; _verificationAdmission.Release(); }
        }

        private async Task VerifyCore(string domainName, HealthCheckType[]? healthCheckTypes,
            string[]? dkimSelectors, ServiceType[]? daneServiceType, int[]? danePorts,
            PortScanProfile[]? portScanProfiles, CancellationToken cancellationToken,
            HealthCheckExecutionOptions? executionOptions, bool useDefaultChecksWhenEmpty) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            IsPublicSuffix = false;
            domainName = ValidateHostName(domainName);
            UpdateIsPublicSuffix(domainName);
            var exec = executionOptions ?? ExecutionOptions;
            if (exec.ResetLogDedupOnRun) {
                _logger.ClearLoggedMessages();
            }
            ApplyExecutionOptions(exec);
            _logger.WriteVerbose("Running health checks for {0}", domainName);
            if (healthCheckTypes == null) {
                healthCheckTypes = DefaultChecks.ToArray();
            } else if (healthCheckTypes.Length == 0 && useDefaultChecksWhenEmpty) {
                healthCheckTypes = DefaultChecks.ToArray();
            }

            healthCheckTypes = healthCheckTypes.Distinct().ToArray();
            ValidateDomainVerificationTypes(healthCheckTypes);
            VerificationRequestedChecks = Array.AsReadOnly(healthCheckTypes.ToArray());

            bool discoverDkim = healthCheckTypes.Contains(HealthCheckType.MAILCLASSIFICATION)
                || healthCheckTypes.Contains(HealthCheckType.MICROSOFT365);
            _runNeedsSmtpDane = healthCheckTypes.Contains(HealthCheckType.MAILCLASSIFICATION);
            var totalChecks = healthCheckTypes.Length;
            var processedChecks = 0;

            var actions = new Dictionary<HealthCheckType, Func<Task>> {
                [HealthCheckType.DMARC] = () => VerifyDMARC(domainName, cancellationToken),
                [HealthCheckType.SPF] = () => EnsureSpfAsync(domainName, cancellationToken),
                [HealthCheckType.DKIM] = () => VerifyDkimCoreAsync(domainName, dkimSelectors ?? Definitions.DKIMSelectors.GuessSelectors().ToArray(), exec.IncludeMissingDkimSelectors, cancellationToken, discoverDkim),
                [HealthCheckType.MX] = () => VerifyMX(domainName, cancellationToken),
                [HealthCheckType.REVERSEDNS] = () => VerifyReverseDnsAsync(domainName, cancellationToken),
                [HealthCheckType.FCRDNS] = () => VerifyFcrDnsAsync(domainName, cancellationToken),
                [HealthCheckType.CAA] = () => VerifyCAA(domainName, cancellationToken),
                [HealthCheckType.ZONETRANSFER] = () => VerifyZoneTransfer(domainName, cancellationToken),
                [HealthCheckType.DANE] = () => VerifyDaneAsync(domainName, daneServiceType, danePorts, cancellationToken),
                [HealthCheckType.SPFFLATTENED] = () => VerifySpfFlattenedAsync(domainName, cancellationToken),
                [HealthCheckType.DNSSEC] = () => VerifyDNSSEC(domainName, cancellationToken),
                [HealthCheckType.DNSBL] = () => VerifyDNSBL(domainName, cancellationToken),
                [HealthCheckType.MTASTS] = () => VerifyMTASTS(domainName, cancellationToken),
                [HealthCheckType.TLSRPT] = () => VerifyTLSRPT(domainName, cancellationToken),
                [HealthCheckType.BIMI] = () => VerifyBIMI(domainName, skipIndicatorDownload: exec.SkipBimiIndicatorDownload, cancellationToken: cancellationToken),
                [HealthCheckType.IDENTITYPROVIDER] = () => VerifyIdpInfo(domainName, cancellationToken),
                [HealthCheckType.AUTODISCOVER] = () => VerifyAutodiscover(domainName, cancellationToken),
                [HealthCheckType.SECURITYTXT] = () => VerifySecurityTxt(domainName, cancellationToken),
                [HealthCheckType.ROBOTS] = () => VerifyRobotsAsync(domainName, cancellationToken),
                [HealthCheckType.SITEMAP] = () => VerifySitemapAsync(domainName, cancellationToken),
                [HealthCheckType.SOA] = () => VerifySOA(domainName, cancellationToken),
                [HealthCheckType.OPENRELAY] = () => VerifyOpenRelay(domainName, 25, cancellationToken),
                [HealthCheckType.OPENRESOLVER] = () => VerifyOpenResolver(domainName, cancellationToken),
                [HealthCheckType.STARTTLS] = () => VerifySTARTTLS(domainName, 25, cancellationToken),
                [HealthCheckType.SMTPTLS] = () => VerifySMTPTLS(domainName, 25, cancellationToken),
                [HealthCheckType.IMAPTLS] = () => VerifyIMAPTLS(domainName, cancellationToken),
                [HealthCheckType.POP3TLS] = () => VerifyPOP3TLS(domainName, cancellationToken),
                [HealthCheckType.SMTPBANNER] = () => VerifySMTPBanner(domainName, 25, cancellationToken),
                [HealthCheckType.SMTPAUTH] = () => VerifySmtpAuth(domainName, 25, cancellationToken),
                [HealthCheckType.MAILLATENCY] = () => VerifyMailLatency(domainName, 25, cancellationToken),
                [HealthCheckType.HPKP] = () => VerifyHpkpAsync(domainName, cancellationToken),
                [HealthCheckType.CONTACT] = () => VerifyContactInfo(domainName, cancellationToken),
                [HealthCheckType.MESSAGEHEADER] = () => VerifyMessageHeaderAsync(cancellationToken),
                [HealthCheckType.DANGLINGCNAME] = () => VerifyDanglingCname(domainName, cancellationToken),
                [HealthCheckType.TTL] = () => VerifyDnsTtlAsync(domainName, cancellationToken),
                [HealthCheckType.PORTAVAILABILITY] = () => CheckPortAvailability(domainName, null, cancellationToken),
                [HealthCheckType.PORTSCAN] = () => ScanPorts(domainName, null, portScanProfiles, cancellationToken),
                [HealthCheckType.SNMP] = () => CheckSnmpHost(domainName, 161, cancellationToken),
                [HealthCheckType.NTP] = () => TestNtpServer(domainName, cancellationToken: cancellationToken),
                [HealthCheckType.AGENTREADINESS] = () => VerifyAgentReadinessAsync(domainName, cancellationToken),
                [HealthCheckType.IPNEIGHBOR] = () => CheckIPNeighbors(domainName, cancellationToken),
                [HealthCheckType.IPENRICHMENT] = () => VerifyIpEnrichmentAsync(domainName, cancellationToken),
                [HealthCheckType.RPKI] = () => VerifyRPKI(domainName, cancellationToken),
                [HealthCheckType.RDAP] = () => QueryRDAP(domainName, cancellationToken),
                [HealthCheckType.WHOIS] = () => CheckWHOIS(domainName, cancellationToken),
                [HealthCheckType.DNSTUNNELING] = () => CheckDnsTunnelingAsync(domainName, cancellationToken),
                [HealthCheckType.TYPOSQUATTING] = () => VerifyTyposquatting(domainName, cancellationToken),
                [HealthCheckType.WILDCARDDNS] = () => VerifyWildcardDns(domainName, 3, cancellationToken),
                [HealthCheckType.EDNSSUPPORT] = () => VerifyEdnsSupport(domainName, cancellationToken),
                [HealthCheckType.DNSHEALTH] = () => VerifyDnsHealth(domainName, cancellationToken),
                [HealthCheckType.DNSAMPLIFICATION] = () => VerifyDnsAmplification(domainName, cancellationToken),
                [HealthCheckType.DNSOVERTLS] = () => VerifyDnsOverTls(domainName, cancellationToken),
                [HealthCheckType.FLATTENINGSERVICE] = () => VerifyFlatteningServiceAsync(domainName, cancellationToken),
                [HealthCheckType.APEXADDRESS] = () => VerifyApexAddresses(domainName, cancellationToken),
                [HealthCheckType.MAILCLASSIFICATION] = () => VerifyMailClassificationAsync(domainName, cancellationToken),
                [HealthCheckType.THREATINTEL] = () => VerifyThreatIntel(domainName, cancellationToken),
                [HealthCheckType.THREATFEED] = () => VerifyThreatFeed(domainName, cancellationToken),
	                [HealthCheckType.DIRECTORYEXPOSURE] = () => VerifyDirectoryExposure(domainName, cancellationToken),
	                [HealthCheckType.SUBDOMAINS] = () => VerifySubdomainsAsync(domainName, cancellationToken),
	                [HealthCheckType.DNSINVENTORY] = () => VerifyDnsInventoryAsync(domainName, cancellationToken),
	                [HealthCheckType.DNSTRACE] = () => VerifyDnsTraceAsync(domainName, cancellationToken),
	                [HealthCheckType.CTTIMELINE] = () => VerifyCtTimelineAsync(domainName, cancellationToken),
                    [HealthCheckType.DNSPROPAGATION] = () => VerifyDnsPropagationAsync(domainName, cancellationToken),
                    [HealthCheckType.MICROSOFT365] = () => VerifyMicrosoft365TenantAsync(domainName, cancellationToken)
		            };

            ConfigureSharedChecks(actions, domainName, cancellationToken, exec);
            // Shared NS and website operations are valid selections too. Reject invalid
            // selections only after all supported actions exist, without replacing evidence.
            foreach (var check in healthCheckTypes) {
                if (!actions.ContainsKey(check)) { throw new NotSupportedException($"Health check type not implemented: {(int)check}"); }
            }
            ResetExecutionState();
            LastVerifiedChecks = Array.Empty<HealthCheckType>();
            VerificationDomain = domainName;
            Task? prestartedDaneTask = null;
            if (healthCheckTypes.Contains(HealthCheckType.DANE)) {
                actions[HealthCheckType.DANE] = async () => {
                    try { await EnsureDaneAsync(domainName, daneServiceType, danePorts, cancellationToken).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                    catch (Exception exception) when (exception is not OutOfMemoryException) {
                        cancellationToken.ThrowIfCancellationRequested();
                        RecordCheckFailure(HealthCheckType.DANE, domainName, exception);
                    }
                };
            }

            // Composite-only dependencies use their narrow original policies. When
            // explicitly selected, the richer requested selector/download plan wins.
            if (!healthCheckTypes.Contains(HealthCheckType.DKIM)) {
                actions[HealthCheckType.DKIM] = () => VerifyDKIM(domainName, Array.Empty<string>(), cancellationToken);
            }
            if (!healthCheckTypes.Contains(HealthCheckType.BIMI)) {
                actions[HealthCheckType.BIMI] = () => VerifyBIMI(domainName, true, cancellationToken);
            }
            if (!healthCheckTypes.Contains(HealthCheckType.DANE)) {
                actions[HealthCheckType.DANE] = () => EnsureDaneAsync(domainName, new[] { ServiceType.SMTP }, null, cancellationToken);
            }
            int checkParallelism = exec.EnableParallelism ? exec.GetEffectiveMaxParallelism() : 1;
            using var checkAdmission = new SemaphoreSlim(checkParallelism, checkParallelism);
            ConfigureRunOperations(actions, domainName, healthCheckTypes, checkAdmission, checkParallelism == 1, cancellationToken);
            if (_runNeedsSmtpDane || (healthCheckTypes.Contains(HealthCheckType.DANE)
                && (healthCheckTypes.Contains(HealthCheckType.SMTPTLS) || healthCheckTypes.Contains(HealthCheckType.MTASTS)))) {
                prestartedDaneTask = actions[HealthCheckType.DANE]();
            }
            var auxiliaryTasks = StartAuxiliaryChecks(domainName, exec, cancellationToken);
            if (prestartedDaneTask != null) { auxiliaryTasks.Add(prestartedDaneTask); }

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
                try {
                    await actions[healthCheckType]();
                    cancellationToken.ThrowIfCancellationRequested();
                } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    if (IsCheckAdmitted(healthCheckType)) { RecordCheckCancellation(healthCheckType, domainName); }
                    throw;
                } catch (Exception exception) when (exception is not OutOfMemoryException) {
                    cancellationToken.ThrowIfCancellationRequested();
                    RecordCheckFailure(healthCheckType, domainName, exception);
                }
            }

            async Task RunCheckWithProgressAsync(HealthCheckType healthCheckType) {
                await RunCheckAsync(healthCheckType).ConfigureAwait(false);
                var done = Interlocked.Increment(ref processedChecks);
                _logger.WriteInformation(HasCheckExecutionFailure(healthCheckType)
                    ? "{0} check did not complete" : "{0} check completed", healthCheckType);
                ReportProgress(healthCheckType.ToString(), done);
            }

            Exception? executionFailure = null;
            try {
                if (!exec.EnableParallelism || totalChecks <= 1) {
                    _logger.WriteVerbose("Parallel execution disabled; running checks sequentially.");
                    foreach (var healthCheckType in healthCheckTypes) {
                        ReportProgress(healthCheckType.ToString(), processedChecks);
                        await RunCheckAsync(healthCheckType);
                        processedChecks++;
                        _logger.WriteInformation(HasCheckExecutionFailure(healthCheckType)
                            ? "{0} check did not complete" : "{0} check completed", healthCheckType);
                        ReportProgress(healthCheckType.ToString(), processedChecks);
                    }
                } else {
                    var maxParallelism = exec.GetEffectiveMaxParallelism();
                    _logger.WriteVerbose("Parallel execution enabled: max {0} concurrent checks.", maxParallelism);
                    ReportProgress("Starting", 0);
                    var tasks = new List<Task>(healthCheckTypes.Length);
                    bool deferBulk = DnsConfiguration.GetBulkQueryParallelism(exec.GetEffectiveDnsParallelism()) == 0;
                    foreach (var healthCheckType in healthCheckTypes) {
                        if (deferBulk && healthCheckType == HealthCheckType.DNSBL) { continue; }
                        tasks.Add(RunCheckWithProgressAsync(healthCheckType));
                    }
                    await Task.WhenAll(tasks);
                    if (deferBulk) {
                        foreach (var healthCheckType in healthCheckTypes) {
                            if (healthCheckType == HealthCheckType.DNSBL) { await RunCheckWithProgressAsync(healthCheckType); }
                        }
                    }
                }
            } catch (Exception exception) {
                executionFailure = exception;
                throw;
            } finally {
                try { await Task.WhenAll(auxiliaryTasks).ConfigureAwait(false); }
                catch (Exception exception) when (exception is not OutOfMemoryException
                    && (executionFailure != null || HasRecordedCheckFailure())) {
                    // Selected ordinary failures are deferred until independent work finishes.
                    // Draining an auxiliary must not replace that original failure.
                }
                if (cancellationToken.IsCancellationRequested) {
                    foreach (var check in LastVerifiedChecks.Where(check => !_completedVerificationChecks.ContainsKey(check))) {
                        RecordCheckCancellation(check, domainName);
                    }
                }
            }

            // Compute provider inference once core mail checks ran (best-effort; safe if some were skipped)
            try { ComputeEmailProviderMatch(); } catch { /* non-fatal */ }
        }

        /// <summary>
        /// Assesses machine-readable discovery resources and AI-agent readiness for the specified domain or URL.
        /// </summary>
        /// <param name="domainName">Domain, host, or HTTP/HTTPS URL to analyze.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <param name="options">Optional agent-readiness analysis options.</param>
        public Task VerifyAgentReadinessAsync(string domainName, CancellationToken cancellationToken = default, AgentReadinessOptions? options = null) =>
            CompleteDirectCheckAsync(HealthCheckType.AGENTREADINESS, () => VerifyAgentReadinessAsyncDirectCore(domainName, cancellationToken, options), cancellationToken, ownerDomain: domainName);

        private async Task VerifyAgentReadinessAsyncDirectCore(string domainName, CancellationToken cancellationToken = default, AgentReadinessOptions? options = null) {
            var previous = AgentReadinessAnalysis;
            AgentReadinessAnalysis = new AgentReadinessAnalysis {
                HttpHandlerFactory = previous.HttpHandlerFactory
            };
            await AgentReadinessAnalysis.AnalyzeAsync(domainName, _logger, options, cancellationToken).ConfigureAwait(false);
        }

        private Task VerifySpfFlattenedAsync(string domainName, CancellationToken cancellationToken)
            => EnsureSpfAsync(domainName, cancellationToken);

        private async Task VerifyMailClassificationAsync(string domainName, CancellationToken cancellationToken) {
            var classifier = new MailDomainClassifier(this, _logger);
            MailDomainClassification = await classifier.ClassifyAsync(domainName, cancellationToken).ConfigureAwait(false);
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
            var spf = SpfAnalysis;
            var dmarc = DmarcAnalysis;
            var dkim = DKIMAnalysis;
            var whois = WhoisAnalysis;

            var spfValid = spf != null &&
                           spf.SpfRecordExists &&
                           spf.StartsCorrectly &&
                           !spf.ExceedsDnsLookups &&
                           !spf.MultipleSpfRecords;

            var dmarcValid = dmarc != null &&
                             dmarc.DmarcRecordExists &&
                             dmarc.StartsCorrectly &&
                             dmarc.HasMandatoryTags &&
                             dmarc.IsPolicyValid &&
                             dmarc.IsPctValid &&
                             !dmarc.MultipleRecords &&
                             !dmarc.ExceedsCharacterLimit &&
                             dmarc.ValidDkimAlignment &&
                             dmarc.ValidSpfAlignment;

            var dkimValid = dkim != null && dkim.AnalysisResults.Values.Any(a =>
                a.DkimRecordExists && !a.MultipleRecords && a.VersionValid && a.PublicKeyExists &&
                a.ValidPublicKey && a.ValidKeyLength && a.ValidKeyType && a.ValidFlags);

            var hints = new List<string>();
            bool Assessed(HealthCheckType type) => !VerificationCompleted.HasValue || _completedVerificationChecks.ContainsKey(type);

            static void AddHint(List<string> list, HealthCheckType type) {
                var hint = CheckDescriptions.Get(type)?.Remediation;
                if (!string.IsNullOrWhiteSpace(hint)) {
                    list.Add(hint!);
                }
            }

            if (Assessed(HealthCheckType.SPF) && !spfValid && spf?.DnsQueryFailed != true) {
                AddHint(hints, HealthCheckType.SPF);
            }
            if (Assessed(HealthCheckType.DMARC) && !dmarcValid && (dmarc?.DnsQueryFailed != true || dmarc.DmarcRecordExists)) {
                AddHint(hints, HealthCheckType.DMARC);
            }
            if (Assessed(HealthCheckType.DKIM) && !dkimValid) {
                AddHint(hints, HealthCheckType.DKIM);
            }
            if (Assessed(HealthCheckType.MX) && MXAnalysis is { MxRecordExists: false }) {
                AddHint(hints, HealthCheckType.MX);
            }
            if (Assessed(HealthCheckType.DNSSEC) && !(DnsSecAnalysis?.ChainValid ?? false)) {
                AddHint(hints, HealthCheckType.DNSSEC);
            }
            if (Assessed(HealthCheckType.WHOIS) && (whois?.IsExpired == true || whois?.ExpiresSoon == true)) {
                hints.Add("Renew the domain registration.");
            }

            return new DomainSummary {
                AssessedChecks = VerificationCompleted.HasValue ? VerificationCompletedChecks : null,
                HasSpfRecord = spf?.SpfRecordExists ?? false,
                SpfDnsQueryFailed = spf?.DnsQueryFailed ?? false,
                SpfValid = spfValid,
                HasDmarcRecord = dmarc?.DmarcRecordExists ?? false,
                DmarcDnsQueryFailed = dmarc?.DnsQueryFailed ?? false,
                DmarcPolicy = dmarc?.Policy ?? string.Empty,
                DmarcValid = dmarcValid,
                HasDkimRecord = dkim?.AnalysisResults.Values.Any(a => a.DkimRecordExists) ?? false,
                DkimValid = dkimValid,
                HasMxRecord = MXAnalysis?.MxRecordExists ?? false,
                DnsSecValid = DnsSecAnalysis?.ChainValid ?? false,
                DnsSecKeyExpiresSoon = DnsSecAnalysis?.KeyExpiresSoon ?? false,
                IsPublicSuffix = IsPublicSuffix,
                ExpiryDate = whois?.ExpiryDate ?? string.Empty,
                DaysUntilExpiration = whois?.DaysUntilExpiration ?? 0,
                ExpiresSoon = whois?.ExpiresSoon ?? false,
                IsExpired = whois?.IsExpired ?? false,
                RegistrarLocked = whois?.RegistrarLocked ?? false,
                PrivacyProtected = whois?.PrivacyProtected ?? false,
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
            if (!trimmedValue.StartsWith("[", StringComparison.Ordinal) && IPAddress.TryParse(trimmedValue, out var literal)
                && literal.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) {
                trimmedValue = $"[{literal}]";
            }

            // A scheme without a default port retains every explicit endpoint port,
            // including :80 when this authority will later be used for HTTPS.
            if (!Uri.TryCreate($"tcp://{trimmedValue}", UriKind.Absolute, out var uri)) {
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

                if (!Uri.TryCreate($"tcp://{rebuilt}", UriKind.Absolute, out uri)) {
                    throw new ArgumentException($"Invalid host name '{trimmedValue}'.", nameof(domainName));
                }
            }

            if (!string.IsNullOrEmpty(uri.PathAndQuery) && uri.PathAndQuery != "/" ||
                !string.IsNullOrEmpty(uri.Fragment)) {
                throw new ArgumentException($"Invalid host name '{trimmed}'.", nameof(domainName));
            }

            var host = EndpointHostNormalizer.FormatUriHost(uri);
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

        /// <summary>Creates a copy with the specified analyses and the source run's failure provenance.</summary>
        /// <remarks>Requested/completed check sets are restricted to the retained selection. Optional plain HTTP
        /// and takeover phases have no distinct check type; their run outcome and collected evidence are retained.</remarks>
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
                DnsConfiguration = DnsConfiguration.CloneForIndependentOwner(),
                MtaStsPolicyUrlOverride = MtaStsPolicyUrlOverride
            };
            // The public configuration setter enables reuse for a new health check;
            // a snapshot preserves the source owner's explicit transport policy.
            filtered.DnsConfiguration.ReuseResolverClients = DnsConfiguration.ReuseResolverClients;
            filtered.VerificationCompleted = VerificationCompleted;
            filtered.VerificationError = VerificationError;
            filtered.VerificationRequestedChecks = VerificationRequestedChecks.Where(active.Contains).ToArray();
            foreach (var type in VerificationCompletedChecks.Where(active.Contains)) {
                filtered._completedVerificationChecks.TryAdd(type, 0);
            }
            filtered.VerificationPlainHttpCompleted = VerificationPlainHttpCompleted;
            filtered.VerificationTakeoverCompleted = VerificationTakeoverCompleted;
            if (VerificationPlainHttpCompleted.HasValue) { filtered.PlainHttpAnalysis = CloneAnalysis(PlainHttpAnalysis); }
            if (VerificationTakeoverCompleted.HasValue) { filtered.TakeoverCnameAnalysis = CloneAnalysis(TakeoverCnameAnalysis); }

            filtered.DmarcAnalysis = active.Contains(HealthCheckType.DMARC) ? CloneAnalysis(DmarcAnalysis) : null!;
            filtered.SpfAnalysis =
                active.Contains(HealthCheckType.SPF) || active.Contains(HealthCheckType.SPFFLATTENED)
                    ? CloneAnalysis(SpfAnalysis)
                    : null!;
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
            filtered.SmimeaAnalysis = active.Contains(HealthCheckType.SMIMEA) ? CloneAnalysis(SmimeaAnalysis) : null!;
            filtered.DNSBLAnalysis = active.Contains(HealthCheckType.DNSBL) ? CloneAnalysis(DNSBLAnalysis) : null!;
            filtered.DnsSecAnalysis = active.Contains(HealthCheckType.DNSSEC) ? CloneAnalysis(DnsSecAnalysis) : null!;
            filtered.MTASTSAnalysis = active.Contains(HealthCheckType.MTASTS) ? CloneAnalysis(MTASTSAnalysis) : null!;
            filtered.TLSRPTAnalysis = active.Contains(HealthCheckType.TLSRPT) ? CloneAnalysis(TLSRPTAnalysis) : null!;
            filtered.BimiAnalysis = active.Contains(HealthCheckType.BIMI) ? CloneAnalysis(BimiAnalysis) : null!;
            filtered.IdpInfoAnalysis = active.Contains(HealthCheckType.IDENTITYPROVIDER) ? CloneAnalysis(IdpInfoAnalysis) : null!;
            filtered.Microsoft365TenantAnalysis = active.Contains(HealthCheckType.MICROSOFT365) ? CloneAnalysis(Microsoft365TenantAnalysis) : null!;
            filtered.AutodiscoverAnalysis = active.Contains(HealthCheckType.AUTODISCOVER) ? CloneAnalysis(AutodiscoverAnalysis) : null!;
            filtered.AutodiscoverHttpAnalysis = active.Contains(HealthCheckType.AUTODISCOVER) ? CloneAnalysis(AutodiscoverHttpAnalysis) : null!;
            filtered.CertificateAnalysis =
                active.Contains(HealthCheckType.CERT) || active.Contains(HealthCheckType.WEBSITE)
                    ? CloneAnalysis(CertificateAnalysis)
                    : null!;
            filtered.SecurityTXTAnalysis = active.Contains(HealthCheckType.SECURITYTXT) ? CloneAnalysis(SecurityTXTAnalysis) : null!;
            filtered.RobotsTxtAnalysis = active.Contains(HealthCheckType.ROBOTS) ? CloneAnalysis(RobotsTxtAnalysis) : null!;
            filtered.SOAAnalysis = active.Contains(HealthCheckType.SOA) ? CloneAnalysis(SOAAnalysis) : null!;
            filtered.WhoisAnalysis = active.Contains(HealthCheckType.WHOIS) ? CloneAnalysis(WhoisAnalysis) : null!;
            filtered.RdapAnalysis = active.Contains(HealthCheckType.RDAP) ? CloneAnalysis(RdapAnalysis) : null!;
            filtered.OpenRelayAnalysis = active.Contains(HealthCheckType.OPENRELAY) ? CloneAnalysis(OpenRelayAnalysis) : null!;
            filtered.OpenResolverAnalysis = active.Contains(HealthCheckType.OPENRESOLVER) ? CloneAnalysis(OpenResolverAnalysis) : null!;
            filtered.StartTlsAnalysis = active.Contains(HealthCheckType.STARTTLS) ? CloneAnalysis(StartTlsAnalysis) : null!;
            filtered.SmtpTlsAnalysis = active.Contains(HealthCheckType.SMTPTLS) ? CloneAnalysis(SmtpTlsAnalysis) : null!;
            filtered.ImapTlsAnalysis = active.Contains(HealthCheckType.IMAPTLS) ? CloneAnalysis(ImapTlsAnalysis) : null!;
            filtered.Pop3TlsAnalysis = active.Contains(HealthCheckType.POP3TLS) ? CloneAnalysis(Pop3TlsAnalysis) : null!;
            filtered.SmtpBannerAnalysis = active.Contains(HealthCheckType.SMTPBANNER) ? CloneAnalysis(SmtpBannerAnalysis) : null!;
            filtered.SmtpAuthAnalysis = active.Contains(HealthCheckType.SMTPAUTH) ? CloneAnalysis(SmtpAuthAnalysis) : null!;
            filtered.MailLatencyAnalysis = active.Contains(HealthCheckType.MAILLATENCY) ? CloneAnalysis(MailLatencyAnalysis) : null!;
            filtered.HttpAnalysis =
                active.Contains(HealthCheckType.HTTP) || active.Contains(HealthCheckType.WEBSITE)
                    ? CloneAnalysis(HttpAnalysis)
                    : null!;
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
            filtered.IpEnrichmentAnalysis = active.Contains(HealthCheckType.IPENRICHMENT) ? CloneAnalysis(IpEnrichmentAnalysis) : null!;
            filtered.DnsTunnelingAnalysis = active.Contains(HealthCheckType.DNSTUNNELING) ? CloneAnalysis(DnsTunnelingAnalysis) : null!;
            filtered.TyposquattingAnalysis = active.Contains(HealthCheckType.TYPOSQUATTING) ? CloneAnalysis(TyposquattingAnalysis) : null!;
            filtered.ThreatIntelAnalysis = active.Contains(HealthCheckType.THREATINTEL) ? CloneAnalysis(ThreatIntelAnalysis) : null!;
            filtered.ThreatFeedAnalysis = active.Contains(HealthCheckType.THREATFEED) ? CloneAnalysis(ThreatFeedAnalysis) : null!;
            filtered.WildcardDnsAnalysis = active.Contains(HealthCheckType.WILDCARDDNS) ? CloneAnalysis(WildcardDnsAnalysis) : null!;
            filtered.EdnsSupportAnalysis = active.Contains(HealthCheckType.EDNSSUPPORT) ? CloneAnalysis(EdnsSupportAnalysis) : null!;
            filtered.DnsHealthAnalysis = active.Contains(HealthCheckType.DNSHEALTH) ? CloneAnalysis(DnsHealthAnalysis) : null!;
            filtered.DnsAmplificationAnalysis = active.Contains(HealthCheckType.DNSAMPLIFICATION) ? CloneAnalysis(DnsAmplificationAnalysis) : null!;
            filtered.DnsOverTlsAnalysis = active.Contains(HealthCheckType.DNSOVERTLS) ? CloneAnalysis(DnsOverTlsAnalysis) : null!;
            filtered.FlatteningServiceAnalysis = active.Contains(HealthCheckType.FLATTENINGSERVICE) ? CloneAnalysis(FlatteningServiceAnalysis) : null!;
            filtered.DirectoryExposureAnalysis = active.Contains(HealthCheckType.DIRECTORYEXPOSURE) ? CloneAnalysis(DirectoryExposureAnalysis) : null!;
            filtered.NtpAnalysis = active.Contains(HealthCheckType.NTP) ? CloneAnalysis(NtpAnalysis) : null!;
            filtered.AgentReadinessAnalysis = active.Contains(HealthCheckType.AGENTREADINESS) ? CloneAnalysis(AgentReadinessAnalysis) : null!;
            filtered.SitemapAnalysis = active.Contains(HealthCheckType.SITEMAP) ? CloneAnalysis(SitemapAnalysis) : null!;
            filtered.ApexAddressAnalysis = active.Contains(HealthCheckType.APEXADDRESS) ? CloneAnalysis(ApexAddressAnalysis) : null!;
            var mailDomainClassification = MailDomainClassification;
            filtered.MailDomainClassification =
                active.Contains(HealthCheckType.MAILCLASSIFICATION) && mailDomainClassification != null
                    ? CloneAnalysis(mailDomainClassification)
                    : null;
            filtered.SubdomainsAnalysis = active.Contains(HealthCheckType.SUBDOMAINS) ? CloneAnalysis(SubdomainsAnalysis) : null!;
            filtered.DnsInventoryAnalysis = active.Contains(HealthCheckType.DNSINVENTORY) ? CloneAnalysis(DnsInventoryAnalysis) : null!;
            filtered.DnsTraceAnalysis = active.Contains(HealthCheckType.DNSTRACE) ? CloneAnalysis(DnsTraceAnalysis) : null!;
            filtered.CtTimelineAnalysis = active.Contains(HealthCheckType.CTTIMELINE) ? CloneAnalysis(CtTimelineAnalysis) : null!;
            filtered.DnsPropagationSet = active.Contains(HealthCheckType.DNSPROPAGATION) ? CloneAnalysis(DnsPropagationSet) : null!;

            // Cloned analyses must follow the snapshot's independent resolver lifetime.
            CopyExecutionFailuresTo(filtered, active);
            filtered.ApplyDnsConfiguration(filtered.DnsConfiguration);
            return filtered;
        }

        private static readonly MethodInfo _cloneMethod = typeof(object).GetMethod(
                "MemberwiseClone",
                BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Unable to locate MemberwiseClone method.");

        private static readonly Func<object, object> _cloneObject = CreateCloneDelegate();

        private static T CloneAnalysis<T>(T analysis) where T : class {
            return analysis == null ? null! : analysis is CertificateAnalysis certificate
                ? (T)(object)certificate.CloneForSnapshot() : analysis is NSAnalysis ns
                ? (T)(object)ns.CloneForSnapshot() : analysis is HttpAnalysis http
                ? (T)(object)http.CloneForSnapshot() : (T)_cloneObject(analysis);
        }

        private static Func<object, object> CreateCloneDelegate() {
            try {
                return (Func<object, object>)_cloneMethod.CreateDelegate(typeof(Func<object, object>));
            } catch {
                return source => _cloneMethod.Invoke(source, null) ?? throw new InvalidOperationException("MemberwiseClone returned null.");
            }
        }
    }
}
