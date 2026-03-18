using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    private static async Task<HashSet<string>> VerifyDiscoveredSubdomainsResolveAsync(
        IReadOnlyList<string> names,
        CertificateInventoryCaptureOptions options,
        CancellationToken cancellationToken) {
        var resolved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (names == null || names.Count == 0) {
            return resolved;
        }

        var dns = new DnsConfiguration {
            DnsEndpoint = options.DnsEndpoint
        };
        var lockObject = new object();
        var maxParallelism = Math.Max(1, options.DiscoveryParallelism);
        using var semaphore = new SemaphoreSlim(maxParallelism, maxParallelism);
        var tasks = new List<Task>(names.Count);
        foreach (var name in names) {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    var hasAddress = false;
                    var a = await dns.QueryDNS(name, DnsRecordType.A, cancellationToken: cancellationToken).ConfigureAwait(false);
                    if (a != null && a.Length > 0) {
                        hasAddress = true;
                    } else {
                        var aaaa = await dns.QueryDNS(name, DnsRecordType.AAAA, cancellationToken: cancellationToken).ConfigureAwait(false);
                        hasAddress = aaaa != null && aaaa.Length > 0;
                    }

                    if (hasAddress) {
                        lock (lockObject) {
                            resolved.Add(name);
                        }
                    }
                } catch {
                } finally {
                    semaphore.Release();
                }
            }, cancellationToken));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return resolved;
    }

    private static async Task<IReadOnlyList<CertificateMonitor.Entry>> ProbeHttpsAsync(
        IEnumerable<string> httpsTargets,
        CertificateInventoryCaptureOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var list = httpsTargets.Where(target => !string.IsNullOrWhiteSpace(target)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (list.Count == 0) {
            return Array.Empty<CertificateMonitor.Entry>();
        }

        using var monitor = new CertificateMonitor {
            CacheDirectory = options.CacheDirectory,
            PersistInventorySnapshots = false,
            MaxParallelism = Math.Max(1, options.MaxParallelism)
        };
        logger.WriteVerbose("Starting HTTPS probe for {0} endpoint(s).", list.Count);
        if (options.MaxProbeStartsPerSecond > 0) {
            logger.WriteVerbose("Probe start rate limit enabled: up to {0} start(s)/second.", options.MaxProbeStartsPerSecond);
        }
        var rateLimiter = new ProbeStartRateLimiter(options.MaxProbeStartsPerSecond);
        monitor.AnalysisOverride = async (url, port, internalLogger, token) => {
            await rateLimiter.WaitAsync(token).ConfigureAwait(false);
            var analysis = new CertificateAnalysis();
            ConfigureHttpsAnalysis(analysis, options, url);
            await analysis.AnalyzeUrl(url, port, internalLogger, token).ConfigureAwait(false);
            return analysis;
        };

        await monitor.Analyze(list, options.HttpsPort, logger, cancellationToken, showProgress: true).ConfigureAwait(false);
        logger.WriteVerbose("Completed HTTPS probe for {0} endpoint(s).", list.Count);
        return monitor.Results.ToList();
    }

    internal static void ConfigureHttpsAnalysis(CertificateAnalysis analysis, CertificateInventoryCaptureOptions options, string? target = null) {
        if (analysis == null) {
            throw new ArgumentNullException(nameof(analysis));
        }
        if (options == null) {
            throw new ArgumentNullException(nameof(options));
        }

        bool captureExtendedMetadata = options.CaptureExtendedHttpsMetadata;
        bool captureCtMetadata = captureExtendedMetadata || ShouldCaptureTargetedCtMetadata(options, target);

        analysis.CaptureTlsDetails = captureExtendedMetadata;
        analysis.CaptureExtendedMetadata = captureExtendedMetadata;
        analysis.CaptureCtMetadata = captureCtMetadata;
        analysis.PreferTlsHandshakeOnlyProbe = options.PreferTlsHandshakeOnlyProbe;
        analysis.SkipRevocation = options.SkipRevocation || !captureExtendedMetadata;
        analysis.Timeout = options.HttpsTimeout;

        if (!captureCtMetadata || options.CtProfile == CertificateCtEnrichmentProfile.Disabled) {
            analysis.CtLogApiTemplates.Clear();
            analysis.EnableCensysCtSource = false;
            analysis.CensysApiId = null;
            analysis.CensysApiSecret = null;
            analysis.CensysCtApiUrlTemplate = string.Empty;
            analysis.EnableShodanCtSource = false;
            analysis.ShodanApiKey = null;
            analysis.ShodanCtApiUrlTemplate = string.Empty;
            return;
        }

        var allowDefaultPassiveCtTemplate =
            (options.EnablePassiveCtFallback || options.EnablePassiveCtMetadataFallback) &&
            options.IncludeDefaultCtTemplate;
        if (options.CtProfile == CertificateCtEnrichmentProfile.Public || !allowDefaultPassiveCtTemplate) {
            analysis.CtLogApiTemplates.Clear();
        }
        if (allowDefaultPassiveCtTemplate) {
            AddCtTemplateIfMissing(analysis.CtLogApiTemplates, "https://crt.sh/?sha256={0}&output=json");
        }
        foreach (var template in options.CtApiTemplates) {
            AddCtTemplateIfMissing(analysis.CtLogApiTemplates, template);
        }

        var autoEnableCommercialSources = options.CtProfile == CertificateCtEnrichmentProfile.Extended;
        var hasCensysCredentials = !string.IsNullOrWhiteSpace(options.CensysApiId) &&
                                   !string.IsNullOrWhiteSpace(options.CensysApiSecret);
        var hasShodanCredentials = !string.IsNullOrWhiteSpace(options.ShodanApiKey);

        analysis.EnableCensysCtSource = options.EnableCensysCtSource || (autoEnableCommercialSources && hasCensysCredentials);
        analysis.CensysApiId = options.CensysApiId;
        analysis.CensysApiSecret = options.CensysApiSecret;
        if (!string.IsNullOrWhiteSpace(options.CensysCtApiUrlTemplate)) {
            analysis.CensysCtApiUrlTemplate = options.CensysCtApiUrlTemplate!;
        }

        analysis.EnableShodanCtSource = options.EnableShodanCtSource || (autoEnableCommercialSources && hasShodanCredentials);
        analysis.ShodanApiKey = options.ShodanApiKey;
        if (!string.IsNullOrWhiteSpace(options.ShodanCtApiUrlTemplate)) {
            analysis.ShodanCtApiUrlTemplate = options.ShodanCtApiUrlTemplate!;
        }
    }

    private static bool ShouldCaptureTargetedCtMetadata(CertificateInventoryCaptureOptions options, string? target) {
        if (options == null || options.CtMetadataTargetHosts.Count == 0) {
            return false;
        }

        string? normalizedHost = TryNormalizeTargetHost(target);
        if (string.IsNullOrWhiteSpace(normalizedHost)) {
            return false;
        }

        return options.CtMetadataTargetHosts
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host!.Trim().TrimEnd('.'))
            .Contains(normalizedHost, StringComparer.OrdinalIgnoreCase);
    }

    private static string? TryNormalizeTargetHost(string? target) {
        if (string.IsNullOrWhiteSpace(target)) {
            return null;
        }

        if (Uri.TryCreate(target, UriKind.Absolute, out Uri? uri)) {
            return string.IsNullOrWhiteSpace(uri.Host)
                ? null
                : uri.Host.Trim().TrimEnd('.');
        }

        return target!.Trim().TrimEnd('.');
    }

    private static void AddCtTemplateIfMissing(ICollection<string> templates, string? template) {
        if (template == null) {
            return;
        }
        if (string.IsNullOrWhiteSpace(template)) {
            return;
        }
        var trimmed = template.Trim();
        foreach (var existing in templates) {
            if (string.Equals(existing, trimmed, StringComparison.OrdinalIgnoreCase)) {
                return;
            }
        }
        templates.Add(trimmed);
    }

    private static void AppendCtConfigurationWarnings(CertificateInventoryCaptureOptions options, List<string> warnings) {
        if (options.CtProfile == CertificateCtEnrichmentProfile.Disabled) {
            return;
        }

        if (options.EnableCensysCtSource) {
            if (string.IsNullOrWhiteSpace(options.CensysApiId) || string.IsNullOrWhiteSpace(options.CensysApiSecret)) {
                warnings.Add("Censys CT source is enabled but CensysApiId/CensysApiSecret are missing; Censys source will not be used.");
            }
            if (string.IsNullOrWhiteSpace(options.CensysCtApiUrlTemplate)) {
                warnings.Add("Censys CT source is enabled but CensysCtApiUrlTemplate is empty; source may report template errors.");
            }
        } else if (options.CtProfile == CertificateCtEnrichmentProfile.Extended) {
            if (string.IsNullOrWhiteSpace(options.CensysApiId) || string.IsNullOrWhiteSpace(options.CensysApiSecret)) {
                warnings.Add("CT profile 'Extended' can auto-enable Censys when credentials are present. Censys credentials are not configured.");
            }
        }

        if (options.EnableShodanCtSource) {
            if (string.IsNullOrWhiteSpace(options.ShodanApiKey)) {
                warnings.Add("Shodan CT source is enabled but ShodanApiKey is missing; Shodan source will not be used.");
            }
        } else if (options.CtProfile == CertificateCtEnrichmentProfile.Extended) {
            if (string.IsNullOrWhiteSpace(options.ShodanApiKey)) {
                warnings.Add("CT profile 'Extended' can auto-enable Shodan when credentials are present. Shodan API key is not configured.");
            }
        }
    }

    private static async Task<IReadOnlyList<CertificateInventoryEntry>> ProbeMailAsync(
        IReadOnlyList<MailEndpointTarget> mailTargets,
        CertificateInventoryCaptureOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (mailTargets == null || mailTargets.Count == 0) {
            return Array.Empty<CertificateInventoryEntry>();
        }

        var results = new ConcurrentBag<CertificateInventoryEntry>();
        var parallelism = Math.Max(1, options.MaxParallelism);
        var totalTargets = mailTargets.Count;
        var completedTargets = 0;
        logger.WriteVerbose("Starting mail TLS probe for {0} endpoint(s).", totalTargets);
        var rateLimiter = new ProbeStartRateLimiter(options.MaxProbeStartsPerSecond);
        using var gate = new SemaphoreSlim(parallelism, parallelism);
        var tasks = new List<Task>(mailTargets.Count);
        foreach (var target in mailTargets) {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    await rateLimiter.WaitAsync(cancellationToken).ConfigureAwait(false);
                    logger.WriteVerbose("Probing mail endpoint {0}:{1} ({2}).", target.Host, target.Port, target.Service);
                    var analysis = new MailTlsAnalysis {
                        Timeout = options.MailTimeout
                    };
                    await analysis.AnalyzeServer(target.Protocol, target.Host, target.Port, logger, cancellationToken).ConfigureAwait(false);
                    var key = $"{target.Host}:{target.Port}";
                    if (analysis.ServerResults.TryGetValue(key, out var tlsResult)) {
                        results.Add(ToInventoryEntry(target, tlsResult));
                    } else {
                        results.Add(ToInventoryEntry(target, new MailTlsAnalysis.TlsResult()));
                    }
                } catch {
                    results.Add(ToInventoryEntry(target, new MailTlsAnalysis.TlsResult()));
                } finally {
                    var completed = Interlocked.Increment(ref completedTargets);
                    logger.WriteProgress(
                        "CertificateInventoryCapture.Mail",
                        $"{target.Service} {target.Host}:{target.Port}",
                        totalTargets == 0 ? 100d : completed * 100d / totalTargets,
                        completed,
                        totalTargets);
                    gate.Release();
                }
            }, cancellationToken));
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);
        logger.WriteVerbose("Completed mail TLS probe for {0} endpoint(s).", totalTargets);
        return results.ToList();
    }

    private static List<CertificateInventoryEntry> DeduplicateEntries(List<CertificateInventoryEntry> entries) {
        var byEndpoint = new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries) {
            if (entry == null) {
                continue;
            }
            var host = !string.IsNullOrWhiteSpace(entry.ResolvedHost) ? entry.ResolvedHost! : entry.Host;
            var key = $"{host}|{entry.Port}|{entry.Service}";
            if (!byEndpoint.TryGetValue(key, out var existing)) {
                byEndpoint[key] = entry;
                continue;
            }

            if (GetEntryScore(entry) > GetEntryScore(existing)) {
                byEndpoint[key] = entry;
            }
        }

        return byEndpoint.Values
            .OrderBy(e => e.Host, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Port)
            .ThenBy(e => e.Service, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static int GetEntryScore(CertificateInventoryEntry entry) {
        var score = 0;
        if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
            score += 10;
        }
        if (entry.IsReachable) {
            score += 4;
        }
        if (entry.Valid) {
            score += 6;
        }
        if (entry.ChainComplete) {
            score += 2;
        }
        return score;
    }

    private static CertificateInventoryEntry ToInventoryEntry(MailEndpointTarget target, MailTlsAnalysis.TlsResult result) {
        var certificate = result.Certificate;
        var chain = result.Chain != null && result.Chain.Count > 0
            ? result.Chain
            : (certificate != null ? new List<X509Certificate2> { certificate } : new List<X509Certificate2>());
        var root = chain.Count > 0 ? chain[chain.Count - 1] : null;

        var issuerIdentity = CertificateIssuerClassifier.Classify(certificate);
        var rootIdentity = CertificateIssuerClassifier.Classify(root);
        var eku = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);

        var keyAlgorithm = !string.IsNullOrWhiteSpace(result.PublicKeyAlgorithm)
            ? result.PublicKeyAlgorithm!
            : (certificate?.PublicKey?.Oid?.FriendlyName ?? certificate?.PublicKey?.Oid?.Value ?? string.Empty);
        var keySize = result.PublicKeySize ?? GetPublicKeySize(certificate);
        var signatureOid = certificate?.SignatureAlgorithm?.Value ?? string.Empty;
        var sha1Signature = signatureOid == "1.2.840.113549.1.1.5" ||
                            signatureOid == "1.2.840.10040.4.3" ||
                            signatureOid == "1.3.14.3.2.29";
        var rsaPssSignature = signatureOid == "1.2.840.113549.1.1.10";
        var authenticationProfile = string.IsNullOrWhiteSpace(eku.AuthenticationProfile)
            ? CertificateAuthenticationProfileClassifier.Classify(eku)
            : eku.AuthenticationProfile;

        var notBeforeUtc = certificate != null
            ? new DateTimeOffset(certificate.NotBefore.ToUniversalTime())
            : (result.CertificateNotBefore.HasValue ? new DateTimeOffset(result.CertificateNotBefore.Value.ToUniversalTime()) : (DateTimeOffset?)null);
        var notAfterUtc = certificate != null
            ? new DateTimeOffset(certificate.NotAfter.ToUniversalTime())
            : (result.CertificateNotAfter.HasValue ? new DateTimeOffset(result.CertificateNotAfter.Value.ToUniversalTime()) : (DateTimeOffset?)null);
        var isReachable = result.StartTlsAdvertised || certificate != null;
        var valid = certificate != null && result.CertificateValid && !result.IsExpired;
        var chainComplete = certificate != null && result.ChainValid && chain.Count > 1;

        var entry = new CertificateInventoryEntry {
            Host = target.Host,
            ResolvedHost = target.Host,
            Url = $"{target.Scheme}://{target.Host}:{target.Port}",
            Scheme = target.Scheme,
            Port = target.Port,
            Service = target.Service,
            CertificateSubject = certificate?.Subject ?? result.CertificateSubject,
            CertificateIssuer = certificate?.Issuer ?? result.CertificateIssuer,
            CertificateThumbprint = certificate?.Thumbprint ?? result.CertificateThumbprint,
            CertificateSerialNumber = certificate?.SerialNumber ?? result.CertificateSerialNumber,
            CertificateIssuerCommonName = issuerIdentity.CommonName,
            CertificateIssuerOrganization = issuerIdentity.Organization,
            CertificateIssuerNormalized = issuerIdentity.NormalizedName,
            CertificateAuthorityFamily = issuerIdentity.AuthorityFamily,
            CertificateRootSubject = root?.Subject,
            CertificateRootIssuer = root?.Issuer,
            CertificateRootThumbprint = root?.Thumbprint,
            CertificateRootIssuerCommonName = rootIdentity.CommonName,
            CertificateRootIssuerOrganization = rootIdentity.Organization,
            CertificateRootIssuerNormalized = rootIdentity.NormalizedName,
            CertificateRootAuthorityFamily = rootIdentity.AuthorityFamily,
            CertificateChainLength = chain.Count,
            CertificateIntermediateCount = Math.Max(0, chain.Count - 2),
            IsKnownCertificateAuthority = issuerIdentity.IsKnownAuthority,
            IsKnownRootCertificateAuthority = rootIdentity.IsKnownAuthority,
            NotBeforeUtc = notBeforeUtc,
            NotAfterUtc = notAfterUtc,
            Valid = valid,
            Expired = result.IsExpired,
            ChainComplete = chainComplete,
            IsReachable = isReachable,
            IsSelfSigned = IsSelfSigned(certificate),
            HostnameMatch = certificate != null && result.HostnameMatch,
            PresentInCtLogs = false,
            DaysToExpire = result.DaysToExpire,
            DaysValid = result.DaysValid,
            Protocol = result.Protocol.ToString(),
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            WeakKey = keySize > 0 && keySize < 2048,
            Sha1Signature = sha1Signature,
            RsaPssSignature = rsaPssSignature,
            HasEnhancedKeyUsageExtension = eku.HasEnhancedKeyUsageExtension,
            HasAnyExtendedKeyUsageOid = eku.HasAnyExtendedKeyUsageOid,
            AllowsServerAuthentication = eku.AllowsServerAuthentication,
            AllowsClientAuthentication = eku.AllowsClientAuthentication,
            AllowsSecureEmail = eku.AllowsSecureEmail,
            AuthenticationProfile = authenticationProfile,
            CertificateChainSource = target.ChainSource
        };
        entry.CertificateChainSources.Add(target.ChainSource);
        if (eku.Oids.Count > 0) {
            entry.ExtendedKeyUsageOids.AddRange(eku.Oids);
        }
        if (result.CertificateDnsNames.Count > 0) {
            entry.SubjectAlternativeNames.AddRange(result.CertificateDnsNames.Distinct(StringComparer.OrdinalIgnoreCase));
        }
        foreach (var chainElement in chain) {
            if (!string.IsNullOrWhiteSpace(chainElement.Subject)) {
                entry.CertificateChainSubjects.Add(chainElement.Subject);
            }
            if (!string.IsNullOrWhiteSpace(chainElement.Issuer)) {
                entry.CertificateChainIssuers.Add(chainElement.Issuer);
            }
            if (!string.IsNullOrWhiteSpace(chainElement.Thumbprint)) {
                entry.CertificateChainThumbprints.Add(chainElement.Thumbprint);
            }
        }

        return entry;
    }

    private static int GetPublicKeySize(X509Certificate2? certificate) {
        if (certificate == null) {
            return 0;
        }
        try {
            using (var rsa = certificate.GetRSAPublicKey()) {
                if (rsa != null) {
                    return rsa.KeySize;
                }
            }
        } catch {
        }
        try {
            using (var ecdsa = certificate.GetECDsaPublicKey()) {
                if (ecdsa != null) {
                    return ecdsa.KeySize;
                }
            }
        } catch {
        }
        try {
            using (var dsa = certificate.GetDSAPublicKey()) {
                if (dsa != null) {
                    return dsa.KeySize;
                }
            }
        } catch {
        }
        return 0;
    }

    private static bool IsSelfSigned(X509Certificate2? certificate) {
        if (certificate == null) {
            return false;
        }
        if (string.IsNullOrWhiteSpace(certificate.Subject) || string.IsNullOrWhiteSpace(certificate.Issuer)) {
            return false;
        }
        return string.Equals(certificate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase);
    }
}
