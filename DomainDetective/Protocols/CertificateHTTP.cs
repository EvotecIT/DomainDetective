using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using DnsClientX;

namespace DomainDetective {
    /// <summary>
    /// Represents certificate validation results for an HTTP endpoint.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Validation includes hostname matching and chain verification using the
    /// system trust store.
    /// </remarks>
    public partial class CertificateAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>Gets or sets the URL that was checked.</summary>
        public string Url { get; set; } = string.Empty;
        /// <summary>Gets or sets a value indicating whether the certificate chain is valid.</summary>
        public bool IsValid { get; set; }
        /// <summary>Gets or sets a value indicating whether the endpoint was reachable.</summary>
        public bool IsReachable { get; set; }
        /// <summary>Gets the best-effort failure reason when the endpoint probe does not complete successfully.</summary>
        public string? FailureReason { get; private set; }
        /// <summary>Gets the normalized failure kind when the endpoint probe does not complete successfully.</summary>
        public CertificateFailureKind FailureKind { get; private set; }
        /// <summary>Gets whether the certificate matches the requested host.</summary>
        public bool HostnameMatch { get; private set; }
        /// <summary>Gets or sets the number of days until expiry.</summary>
        public int DaysToExpire { get; set; }
        /// <summary>Gets the total validity period in days.</summary>
        public int DaysValid { get; private set; }
        /// <summary>Gets a value indicating whether the certificate has expired.</summary>
        public bool IsExpired { get; private set; }

        /// <summary>Gets the negotiated HTTP protocol version.</summary>
        public Version? ProtocolVersion { get; private set; }

        /// <summary>Gets a value indicating HTTP/2 support.</summary>
        public bool Http2Supported { get; private set; }

        /// <summary>Gets a value indicating HTTP/3 support.</summary>
        public bool Http3Supported { get; private set; }

        /// <summary>Gets the leaf certificate.</summary>
        public X509Certificate2? Certificate { get; set; }

        /// <summary>Gets the certificate chain.</summary>
        public List<X509Certificate2> Chain { get; } = new();
        /// <summary>Most recent source used to populate <see cref="Chain"/>.</summary>
        public string ChainSource { get; private set; } = string.Empty;
        /// <summary>Ordered unique list of chain acquisition sources observed during analysis.</summary>
        public List<string> ChainSourceHistory { get; } = new();
        /// <summary>Gets OCSP endpoints from the certificate.</summary>
        public List<string> OcspUrls { get; } = new();
        /// <summary>Gets CRL endpoints from the certificate.</summary>
        public List<string> CrlUrls { get; } = new();
        /// <summary>Gets a value indicating whether the certificate is revoked according to OCSP.</summary>
        public bool? OcspRevoked { get; private set; }
        /// <summary>Gets a value indicating whether the certificate is revoked according to CRL.</summary>
        public bool? CrlRevoked { get; private set; }
        /// <summary>Gets or sets the HTTP request timeout.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        /// <summary>Gets the actual remote address reached by the most recent observable TCP connection.</summary>
        public IPAddress? RemoteAddress { get; private set; }
        /// <summary>Optional resolver that returns addresses approved for outbound connections.</summary>
        public Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? OutboundAddressResolver { get; set; }
        /// <summary>Gets redirect target hosts observed during the most recent HTTP analysis.</summary>
        public List<string> RedirectTargets { get; } = new();
        /// <summary>Gets DNS names listed in the certificate subject alternative name extension.</summary>
        public List<string> SubjectAlternativeNames { get; } = new();
        /// <summary>Gets wildcard entries with matching subdomains.</summary>
        public Dictionary<string, List<string>> WildcardSubdomains { get; } = new();
        /// <summary>Gets a value indicating whether the certificate contains wildcard names.</summary>
        public bool IsWildcardCertificate { get; private set; }
        /// <summary>Gets a value indicating the certificate secures multiple unrelated hosts.</summary>
        public bool SecuresUnrelatedHosts { get; private set; }
        /// <summary>Gets a value indicating whether the certificate is self-signed.</summary>
        public bool IsSelfSigned { get; private set; }
        /// <summary>Gets the public key algorithm.</summary>
        public string KeyAlgorithm { get; private set; } = string.Empty;
        /// <summary>Gets the key size in bits.</summary>
        public int KeySize { get; private set; }
        /// <summary>Indicates if the certificate uses a key under 2048 bits.</summary>
        public bool WeakKey { get; private set; }
        /// <summary>Indicates if the certificate is signed with SHA-1.</summary>
        public bool Sha1Signature { get; private set; }
        /// <summary>Indicates if the certificate uses RSA-PSS for its signature.</summary>
        public bool RsaPssSignature { get; private set; }
        /// <summary>Indicates if the certificate contains an EKU extension.</summary>
        public bool HasEnhancedKeyUsageExtension { get; private set; }
        /// <summary>Indicates if the certificate contains the Any EKU OID value.</summary>
        public bool HasAnyExtendedKeyUsageOid { get; private set; }

        /// <summary>Represents the has any extended key usage value.</summary>
        [Obsolete("Use HasAnyExtendedKeyUsageOid.")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool HasAnyExtendedKeyUsage {
            get { return HasAnyExtendedKeyUsageOid; }
            private set { HasAnyExtendedKeyUsageOid = value; }
        }
        /// <summary>Indicates if the certificate allows server authentication.</summary>
        public bool AllowsServerAuthentication { get; private set; }
        /// <summary>Indicates if the certificate allows client authentication.</summary>
        public bool AllowsClientAuthentication { get; private set; }
        /// <summary>Indicates if the certificate allows secure email usage.</summary>
        public bool AllowsSecureEmail { get; private set; }
        /// <summary>List of EKU OIDs on the certificate.</summary>
        public List<string> ExtendedKeyUsageOids { get; } = new();
        /// <summary>List of EKU friendly names for the certificate.</summary>
        public List<string> ExtendedKeyUsageFriendlyNames { get; } = new();
        /// <summary>Normalized EKU authentication profile for filtering/reporting.</summary>
        public string AuthenticationProfile { get; private set; } = CertificateAuthenticationProfileClassifier.NoEkuExtension;
        /// <summary>Gets the negotiated TLS protocol when <see cref="CaptureTlsDetails"/> is true.</summary>
        public SslProtocols TlsProtocol { get; private set; }
        /// <summary>Indicates if TLS 1.3 was negotiated.</summary>
        public bool Tls13Used { get; private set; }
        /// <summary>Gets the negotiated cipher algorithm.</summary>
        public string CipherAlgorithm { get; private set; } = string.Empty;
        /// <summary>Gets the cipher strength.</summary>
        public int CipherStrength { get; private set; }
        /// <summary>Gets the negotiated cipher suite name.</summary>
        public string CipherSuite { get; private set; } = string.Empty;
        /// <summary>Gets the Diffie-Hellman key size, if used.</summary>
        public int DhKeyBits { get; private set; }
        /// <summary>Enable gathering TLS protocol and cipher information.</summary>
        public bool CaptureTlsDetails { get; set; }
        /// <summary>Enable slower extended HTTPS metadata collection such as revocation, stapling, protocol probes, grade, and CT queries.</summary>
        public bool CaptureExtendedMetadata { get; set; } = true;
        /// <summary>Enable CT lookup even when the rest of extended HTTPS metadata is disabled.</summary>
        public bool CaptureCtMetadata { get; set; }
        /// <summary>Prefer a certificate-only TLS handshake instead of a full HTTP request when the caller only needs certificate evidence.</summary>
        public bool PreferTlsHandshakeOnlyProbe { get; set; }
        /// <summary>Skip certificate revocation checks.</summary>
        public bool SkipRevocation { get; set; }
        /// <summary>Gets a value indicating whether the certificate is present in public CT logs.</summary>
        public bool PresentInCtLogs { get; private set; }

        /// <summary>Collection of CT log entries retrieved for the certificate.</summary>
        public IReadOnlyList<JsonElement> CtLogEntries => _ctLogEntries;

        /// <summary>Optional override to retrieve CT log data for testing.</summary>
        public Func<string, Task<string>>? CtLogQueryOverride { private get; set; }

        /// <summary>CT log API templates. Each entry should contain a {0} placeholder for the SHA-256 fingerprint.</summary>
        public List<string> CtLogApiTemplates => _ctLogAggregator.ApiTemplates;
        /// <summary>Enables Censys certificate discovery source during CT lookups.</summary>
        public bool EnableCensysCtSource { get; set; }
        /// <summary>Censys API identifier used when <see cref="EnableCensysCtSource"/> is true.</summary>
        public string? CensysApiId { get; set; }
        /// <summary>Censys API secret used when <see cref="EnableCensysCtSource"/> is true.</summary>
        public string? CensysApiSecret { get; set; }
        /// <summary>Censys URL template with {0} placeholder for the SHA-256 fingerprint.</summary>
        public string CensysCtApiUrlTemplate {
            get { return _ctLogAggregator.CensysApiUrlTemplate; }
            set { _ctLogAggregator.CensysApiUrlTemplate = value; }
        }
        /// <summary>Enables Shodan certificate discovery source during CT lookups.</summary>
        public bool EnableShodanCtSource { get; set; }
        /// <summary>Shodan API key used when <see cref="EnableShodanCtSource"/> is true.</summary>
        public string? ShodanApiKey { get; set; }
        /// <summary>Shodan URL template with {0} fingerprint and {1} URL-encoded API key placeholders.</summary>
        public string ShodanCtApiUrlTemplate {
            get { return _ctLogAggregator.ShodanApiUrlTemplate; }
            set { _ctLogAggregator.ShodanApiUrlTemplate = value; }
        }
        /// <summary>Discovery sources queried for certificate evidence in the latest CT lookup.</summary>
        public IReadOnlyList<string> CtDiscoverySources => _ctDiscoverySources;
        /// <summary>Template-format errors captured during the latest CT lookup.</summary>
        public IReadOnlyList<string> CtTemplateFormatErrors => _ctTemplateFormatErrors;

        private readonly List<JsonElement> _ctLogEntries = new();
        private volatile string[] _ctDiscoverySources = Array.Empty<string>();
        private volatile string[] _ctTemplateFormatErrors = Array.Empty<string>();
        private readonly CtLogAggregator _ctLogAggregator = new();
        private const string ChainSourceTlsHandshake = "tls-handshake";
        private const string ChainSourceSslStreamBuild = "sslstream-build";
        private const string ChainSourceLocalBuildOnline = "local-build-online";
        private const string ChainSourceLocalBuildNoCheck = "local-build-no-check";

        /// <summary>Structured assessments captured during certificate checks.</summary>
        public List<Assessment> Assessments { get; } = new();

        /// <summary>Coarse web TLS grade.</summary>
        public GradeLevel GradeLevel { get; private set; } = GradeLevel.Unknown;
        /// <summary>Indicates legacy TLS protocol negotiated.</summary>
        public bool LegacyEnabled { get; private set; }
        /// <summary>Indicates if server supports TLS 1.0 during handshake probe.</summary>
        public bool SupportsTls10 { get; private set; }
        /// <summary>Indicates if server supports TLS 1.1 during handshake probe.</summary>
        public bool SupportsTls11 { get; private set; }
        /// <summary>Indicates if server supports TLS 1.2 during handshake probe.</summary>
        public bool SupportsTls12 { get; private set; }
        /// <summary>Indicates if server supports TLS 1.3 during handshake probe.</summary>
        public bool SupportsTls13 { get; private set; }
        /// <summary>Count of embedded SCTs in the certificate.</summary>
        public int SctCount { get; private set; }
        /// <summary>Indicates whether the certificate includes TLS Feature (OCSP Must-Staple).</summary>
        public bool OcspMustStaple { get; private set; }
        /// <summary>Indicates whether the server stapled an OCSP response during handshake (best-effort, via OpenSSL probe).</summary>
        public bool? OcspStaplingPresent { get; private set; }

        internal CtLogAggregator CtLogs => _ctLogAggregator;

        internal static IEnumerable<string> ExtractMxHosts(IEnumerable<DnsAnswer> records)
        {
            foreach (DnsAnswer record in records)
            {
                string data = record.Data ?? record.DataRaw;
                if (string.IsNullOrWhiteSpace(data))
                {
                    continue;
                }

                string[] parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    string host = parts[1].Trim('.');
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        yield return host;
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the certificate from the specified HTTPS endpoint.
        /// </summary>
        /// <param name="url">URL to query.</param>
        /// <param name="port">Port number to use.</param>
        /// <param name="logger">Logger instance for diagnostics.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeUrl(string url, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            var builder = new UriBuilder(url) { Port = port };
            url = builder.ToString();
            Url = url;
            IsSelfSigned = false;
            FailureReason = null;
            FailureKind = CertificateFailureKind.None;
            RemoteAddress = null;
            RedirectTargets.Clear();
            ResetChainSourceTracking();
            bool capturedHandshakeCertificate = false;
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "CERT", target: url);
            if (ShouldUseTlsHandshakeOnlyProbe()) {
                try {
                    await AnalyzeWithTlsHandshakeOnlyAsync(url, port, cancellationToken).ConfigureAwait(false);
                    if (Certificate != null) {
                        await FinalizeCapturedCertificateAsync(url, port, logger, cancellationToken).ConfigureAwait(false);
                    }
                } catch (Exception ex) {
                    ex = NormalizeProbeException(ex, cancellationToken);
                    IsReachable = false;
                    FailureReason = BuildFailureReason(ex);
                    FailureKind = CertificateFailureClassifier.Classify(ex);
                    logger.WriteErrorCode(CertificateHttpCodes.ConnectFailed, "Exception reaching {0}: {1}", url, BuildFailureLogMessage(ex));
                }

                return;
            }

            using (var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10, CheckCertificateRevocationList = !SkipRevocation }) {
                handler.ServerCertificateCustomValidationCallback = (HttpRequestMessage requestMessage, X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors policyErrors) => {
                    if (certificate == null) {
                        return false;
                    }

                    if (!capturedHandshakeCertificate) {
                        var leaf = chain != null && chain.ChainElements.Count > 0
                            ? chain.ChainElements[0].Certificate
                            : certificate;
                        Certificate = CertificateLoaderCompat.Clone(leaf);

                        Chain.Clear();
                        if (chain != null) {
                            foreach (var element in chain.ChainElements) {
                                Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
                            }
                        }
                        RecordChainSource(ChainSourceTlsHandshake);
                        IsSelfSigned = IsSelfSignedCertificate(Certificate);
                        IsValid = policyErrors == SslPolicyErrors.None;
                        HostnameMatch = (policyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                        capturedHandshakeCertificate = true;
                    }
                    return true;
                };
                using (var client = new HttpClient(handler)) {
                    client.Timeout = Timeout;
                    try {
#if NET8_0_OR_GREATER
                        var request = new HttpRequestMessage(HttpMethod.Get, url) {
                            Version = HttpVersion.Version30,
                            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                        };
                        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
                        CaptureRedirectTarget(uri: response.RequestMessage?.RequestUri, originalUrl: url);
                        IsReachable = response.IsSuccessStatusCode;
                        ProtocolVersion = response.Version;
                        Http3Supported = response.Version >= HttpVersion.Version30;
                        Http2Supported = response.Version >= HttpVersion.Version20;
#else
                        var request = new HttpRequestMessage(HttpMethod.Get, url);
                        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
                        CaptureRedirectTarget(uri: response.RequestMessage?.RequestUri, originalUrl: url);
                        IsReachable = response.IsSuccessStatusCode;
                        ProtocolVersion = response.Version;
                        Http2Supported = response.Version.Major >= 2;
                        Http3Supported = false;
#endif
                        if (Certificate == null && Http3Supported) {
                            CancellationTokenSource? timeoutCts = null;
                            try {
                                var uri = new Uri(url);
                                timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                                timeoutCts.CancelAfter(Timeout);
                                using var tcp = await ConnectDirectAsync(uri.Host, port, timeoutCts.Token).ConfigureAwait(false);
                                using var ssl = new SslStream(tcp.GetStream(), false, (sender, certificate, chain, errors) => {
                                    HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                                    return errors == SslPolicyErrors.None;
                                });
                                await ssl.AuthenticateAsClientAsync(uri.Host, null, SslProtocols.None, !SkipRevocation).WaitWithCancellation(timeoutCts.Token);
                                if (ssl.RemoteCertificate is X509Certificate2 cert) {
                                    Certificate = CertificateLoaderCompat.Clone(cert);
                                    var xchain = new X509Chain();
                                    xchain.Build(cert);
                                    Chain.Clear();
                                    foreach (var element in xchain.ChainElements) {
                                        Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
                                    }
                                    RecordChainSource(ChainSourceSslStreamBuild);
                                    IsSelfSigned = IsSelfSignedCertificate(Certificate);
                                }
                            } catch (Exception ex) {
                                ex = NormalizeProbeException(ex, cancellationToken, timeoutCts);
                                logger.WriteErrorCode(CertificateHttpCodes.FetchFailed, "Error retrieving certificate for {0}: {1}", url, ex.ToString());
                            } finally {
                                timeoutCts?.Dispose();
                            }
                        }
                        if (Certificate != null) {
                            await FinalizeCapturedCertificateAsync(url, port, logger, cancellationToken).ConfigureAwait(false);
                        }
                    } catch (Exception ex) {
                        ex = NormalizeProbeException(ex, cancellationToken);
                        IsReachable = false;
                        FailureReason = BuildFailureReason(ex);
                        FailureKind = CertificateFailureClassifier.Classify(ex);
                        logger.WriteErrorCode(CertificateHttpCodes.ConnectFailed, "Exception reaching {0}: {1}", url, BuildFailureLogMessage(ex));
                    }
                }
            }
        }

        internal bool ShouldUseTlsHandshakeOnlyProbe()
        {
            return PreferTlsHandshakeOnlyProbe && !CaptureExtendedMetadata && !CaptureTlsDetails;
        }

        private async Task AnalyzeWithTlsHandshakeOnlyAsync(string url, int port, CancellationToken cancellationToken)
        {
            var uri = new Uri(url);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            using var tcp = await ConnectDirectAsync(uri.Host, port, timeoutCts.Token).ConfigureAwait(false);
            using var ssl = new SslStream(
                tcp.GetStream(),
                false,
                (sender, certificate, chain, errors) =>
                {
                    HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                    IsValid = errors == SslPolicyErrors.None;
                    return true;
                });
            await ssl.AuthenticateAsClientAsync(uri.Host, null, SslProtocols.None, !SkipRevocation)
                .WaitWithCancellation(timeoutCts.Token)
                .ConfigureAwait(false);

            IsReachable = true;
            if (ssl.RemoteCertificate == null)
            {
                return;
            }

            Certificate = CertificateLoaderCompat.LoadCertificate(ssl.RemoteCertificate.Export(X509ContentType.Cert));
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
            chain.Build(Certificate);
            Chain.Clear();
            foreach (X509ChainElement element in chain.ChainElements)
            {
                Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
            }

            RecordChainSource(ChainSourceSslStreamBuild);
            IsSelfSigned = IsSelfSignedCertificate(Certificate);
        }

        internal async Task<TcpClient> ConnectDirectAsync(string host, int port, CancellationToken cancellationToken) {
            if (OutboundAddressResolver == null) {
                var client = new TcpClient();
                await client.ConnectAsync(host, port).WaitWithCancellation(cancellationToken).ConfigureAwait(false);
                CaptureRemoteAddress(client);
                return client;
            }

            var addresses = await OutboundAddressResolver(host, cancellationToken).ConfigureAwait(false);
            Exception? lastError = null;
            foreach (var address in addresses) {
                var client = new TcpClient(address.AddressFamily);
                try {
                    await client.ConnectAsync(address, port).WaitWithCancellation(cancellationToken).ConfigureAwait(false);
                    CaptureRemoteAddress(client);
                    return client;
                } catch (Exception ex) when (ex is not OperationCanceledException) {
                    lastError = ex;
                    client.Dispose();
                }
            }
            throw new SocketException(lastError is SocketException socketError ? socketError.ErrorCode : (int)SocketError.HostUnreachable);
        }

        private void CaptureRemoteAddress(TcpClient client) {
            if (client.Client.RemoteEndPoint is IPEndPoint endpoint) {
                RemoteAddress = endpoint.Address.IsIPv4MappedToIPv6
                    ? endpoint.Address.MapToIPv4()
                    : endpoint.Address;
            }
        }

        private void CaptureRedirectTarget(Uri? uri, string originalUrl) {
            if (uri == null || !Uri.TryCreate(originalUrl, UriKind.Absolute, out Uri? original) ||
                string.Equals(uri.Host, original.Host, StringComparison.OrdinalIgnoreCase)) {
                return;
            }
            if (!RedirectTargets.Contains(uri.Host, StringComparer.OrdinalIgnoreCase)) {
                RedirectTargets.Add(uri.Host);
            }
        }

        internal static Exception NormalizeProbeException(
            Exception exception,
            CancellationToken callerCancellationToken,
            CancellationTokenSource? probeTimeoutSource = null)
        {
            if (exception == null) {
                throw new ArgumentNullException(nameof(exception));
            }

            if (callerCancellationToken.IsCancellationRequested) {
                return exception;
            }

            bool timeoutTriggered = probeTimeoutSource?.IsCancellationRequested == true;
            if (!timeoutTriggered &&
                exception is not TaskCanceledException &&
                exception is not OperationCanceledException) {
                return exception;
            }

            if (timeoutTriggered ||
                exception is TaskCanceledException ||
                exception is OperationCanceledException) {
                return new TimeoutException("The request timed out.", exception);
            }

            return exception;
        }

        private async Task FinalizeCapturedCertificateAsync(string url, int port, InternalLogger logger, CancellationToken cancellationToken)
        {
            EnsureChainBuilt(Certificate!);
            PopulateKeyInfo();
            if (CaptureTlsDetails) {
                await PopulateTlsInfo(new Uri(url), port, cancellationToken).ConfigureAwait(false);
            }
            DaysToExpire = (int)(Certificate!.NotAfter - DateTime.Now).TotalDays;
            DaysValid = (int)(Certificate!.NotAfter - Certificate!.NotBefore).TotalDays;
            IsExpired = Certificate!.NotAfter < DateTime.Now;
            if (CaptureExtendedMetadata && !SkipRevocation) {
                await QueryRevocationEndpoints(cancellationToken).ConfigureAwait(false);
            }
            PopulateSubjectAlternativeNames();
            if (CaptureExtendedMetadata) {
                PopulateSctAndTlsFeature(logger);
                await ProbeProtocolSupport(new Uri(url), port, logger, cancellationToken).ConfigureAwait(false);
                await ProbeOcspStaplingWithOpenSsl(new Uri(url), port, logger, cancellationToken).ConfigureAwait(false);
                // Compute grade once we have basic data (and optional TLS details)
                ComputeGrade(logger);
            }
            if (CaptureExtendedMetadata || CaptureCtMetadata) {
                await QueryCtLogs(cancellationToken).ConfigureAwait(false);
            }
        }

        internal static string? BuildFailureReason(Exception? exception)
        {
            if (exception == null)
            {
                return null;
            }

            var parts = new List<string>();
            bool timeoutMarkerPresent = false;
            Exception? current = exception;
            while (current != null)
            {
                string message = current.Message?.Trim() ?? string.Empty;
                bool suppressGenericCancellationMessage =
                    timeoutMarkerPresent &&
                    (current is TaskCanceledException || current is OperationCanceledException) &&
                    IsGenericCancellationMessage(message);
                if (!suppressGenericCancellationMessage &&
                    !string.IsNullOrWhiteSpace(message) &&
                    !parts.Any(existing => string.Equals(existing, message, StringComparison.OrdinalIgnoreCase)))
                {
                    parts.Add(message);
                }

                if (current is SocketException socketException)
                {
                    string socketCode = "SocketError:" + socketException.SocketErrorCode;
                    if (!parts.Any(existing => string.Equals(existing, socketCode, StringComparison.OrdinalIgnoreCase)))
                    {
                        parts.Add(socketCode);
                    }
                }

#if NET8_0_OR_GREATER
                if (current is HttpRequestException httpRequestException)
                {
                    string requestErrorMarker = "HttpRequestError:" + httpRequestException.HttpRequestError;
                    if (!parts.Any(existing => string.Equals(existing, requestErrorMarker, StringComparison.OrdinalIgnoreCase)))
                    {
                        parts.Add(requestErrorMarker);
                    }

                    if (httpRequestException.StatusCode.HasValue)
                    {
                        string statusCode = "HttpStatus:" + (int)httpRequestException.StatusCode.Value;
                        if (!parts.Any(existing => string.Equals(existing, statusCode, StringComparison.OrdinalIgnoreCase)))
                        {
                            parts.Add(statusCode);
                        }
                    }
                }
#endif

                if (current is TimeoutException)
                {
                    const string timeoutMarker = "FailureKind:Timeout";
                    if (!parts.Any(existing => string.Equals(existing, timeoutMarker, StringComparison.OrdinalIgnoreCase)))
                    {
                        parts.Add(timeoutMarker);
                    }

                    timeoutMarkerPresent = true;
                }

                if (!timeoutMarkerPresent &&
                    (current is TaskCanceledException ||
                     current is OperationCanceledException))
                {
                    const string cancelledMarker = "FailureKind:Cancelled";
                    if (!parts.Any(existing => string.Equals(existing, cancelledMarker, StringComparison.OrdinalIgnoreCase)))
                    {
                        parts.Add(cancelledMarker);
                    }
                }

                current = current.InnerException;
            }

            CertificateFailureKind failureKind = CertificateFailureClassifier.Classify(exception);
            if (failureKind != CertificateFailureKind.None &&
                failureKind != CertificateFailureKind.Unknown)
            {
                string marker = CertificateFailureClassifier.ToMarker(failureKind);
                if (!parts.Any(existing => string.Equals(existing, marker, StringComparison.OrdinalIgnoreCase)))
                {
                    parts.Add(marker);
                }
            }

            return parts.Count == 0 ? exception.GetType().Name : string.Join(" | ", parts);
        }

        private static bool IsGenericCancellationMessage(string? message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return false;
            }

            string normalized = message?.Trim() ?? string.Empty;
            return string.Equals(normalized, "A task was canceled.", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(normalized, "The operation was canceled.", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(normalized, "Operation canceled.", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool ShouldLogConnectivityFailureAsSummary(Exception? exception)
        {
            Exception? current = exception;
            while (current != null)
            {
                if (current is SocketException ||
                    current is TimeoutException ||
                    current is TaskCanceledException ||
                    current is OperationCanceledException ||
                    current is AuthenticationException)
                {
                    return true;
                }

#if NET8_0_OR_GREATER
                if (current is HttpRequestException)
                {
                    return true;
                }
#endif

                current = current.InnerException;
            }

            return false;
        }

        internal static string BuildFailureLogMessage(Exception? exception)
        {
            if (exception == null)
            {
                return string.Empty;
            }

            if (ShouldLogConnectivityFailureAsSummary(exception))
            {
                return BuildFailureReason(exception) ?? exception.Message ?? exception.GetType().Name;
            }

            return exception.ToString();
        }

        private async Task QueryRevocationEndpoints(CancellationToken cancellationToken) {
            if (SkipRevocation) {
                return;
            }
            OcspUrls.Clear();
            CrlUrls.Clear();
            OcspRevoked = null;
            CrlRevoked = null;
            try {
                var certificate = Certificate;
                if (certificate == null) {
                    return;
                }
                var parser = new X509CertificateParser();
                var bcCert = parser.ReadCertificate(certificate.RawData);

                var aiaExt = bcCert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
                if (aiaExt != null) {
                    var seq = (Asn1Sequence)Asn1Object.FromByteArray(aiaExt.GetOctets());
                    foreach (var obj in seq) {
                        var ad = AccessDescription.GetInstance(obj);
                        if (ad.AccessMethod.Equals(new DerObjectIdentifier("1.3.6.1.5.5.7.48.1"))) {
                            var name = GeneralName.GetInstance(ad.AccessLocation.ToAsn1Object());
                            if (name.TagNo == GeneralName.UniformResourceIdentifier) {
                                var uri = DerIA5String.GetInstance(name.Name).GetString();
                                OcspUrls.Add(uri);
                            }
                        }
                    }
                }

                var crlExt = bcCert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
                if (crlExt != null) {
                    var cdp = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(crlExt.GetOctets()));
                    foreach (var dp in cdp.GetDistributionPoints()) {
                        var names = dp.DistributionPointName?.Name as GeneralNames;
                        if (names == null) {
                            continue;
                        }
                        foreach (var gn in names.GetNames()) {
                            if (gn.TagNo == GeneralName.UniformResourceIdentifier) {
                                var uri = DerIA5String.GetInstance(gn.Name).GetString();
                                CrlUrls.Add(uri);
                            }
                        }
                    }
                }

                if (OcspUrls.Count > 0 && Chain.Count > 1) {
                    var issuer = parser.ReadCertificate(Chain[1].RawData);
#pragma warning disable CS0618
                    var id = new CertificateID(CertificateID.HashSha1, issuer, bcCert.SerialNumber);
#pragma warning restore CS0618
                    var gen = new OcspReqGenerator();
                    gen.AddRequest(id);
                    var req = gen.Generate();
                    var client = SharedHttpClient.Instance;
                    using var content = new ByteArrayContent(req.GetEncoded());
                    content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");
                    using var resp = await client.PostAsync(OcspUrls[0], content, cancellationToken);
                    if (resp.IsSuccessStatusCode) {
                        var bytes = await resp.Content.ReadAsByteArrayAsync();
                        OcspRevoked = ParseOcspResponse(bytes);
                    }
                }

                if (CrlUrls.Count > 0) {
                    var client = SharedHttpClient.Instance;
                    using var resp = await client.GetAsync(CrlUrls[0], cancellationToken);
                    if (resp.IsSuccessStatusCode) {
                        var bytes = await resp.Content.ReadAsByteArrayAsync();
                        var crl = new X509CrlParser().ReadCrl(bytes);
                        CrlRevoked = crl.IsRevoked(bcCert);
                    }
                }
            } catch {
                // ignore revocation failures
            }
        }

        /// <summary>Parses an OCSP response and returns the revocation status.</summary>
        /// <param name="response">OCSP response bytes.</param>
        /// <returns><c>true</c> if revoked, <c>false</c> if valid, <c>null</c> if inconclusive.</returns>
        internal static bool? ParseOcspResponse(byte[] response) {
            var ocspResp = new OcspResp(response);
            if (ocspResp.Status != OcspRespStatus.Successful) {
                return null;
            }

            var basic = (BasicOcspResp)ocspResp.GetResponseObject();
            if (basic.Responses.Length == 0) {
                return null;
            }

            var status = basic.Responses[0].GetCertStatus();
            return status switch {
                RevokedStatus => true,
                UnknownStatus => null,
                _ => false
            };
        }

        private async Task QueryCtLogs(CancellationToken cancellationToken)
        {
            PresentInCtLogs = false;
            _ctLogEntries.Clear();
            _ctDiscoverySources = Array.Empty<string>();
            _ctTemplateFormatErrors = Array.Empty<string>();
            if (Certificate == null)
            {
                return;
            }
            byte[] hashBytes;
#if NET8_0_OR_GREATER
            hashBytes = Certificate.GetCertHash(HashAlgorithmName.SHA256);
#else
            using (var sha = SHA256.Create()) {
                hashBytes = sha.ComputeHash(Certificate.RawData);
            }
#endif
            var fingerprint = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLowerInvariant();

            _ctLogAggregator.QueryOverride = CtLogQueryOverride;
            _ctLogAggregator.EnableCensysSource = EnableCensysCtSource;
            _ctLogAggregator.EnableShodanSource = EnableShodanCtSource;
            _ctLogAggregator.CensysApiId = FirstNonEmpty(CensysApiId, Environment.GetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_ID"));
            _ctLogAggregator.CensysApiSecret = FirstNonEmpty(CensysApiSecret, Environment.GetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_SECRET"));
            _ctLogAggregator.ShodanApiKey = FirstNonEmpty(ShodanApiKey, Environment.GetEnvironmentVariable("DOMAINDETECTIVE_SHODAN_API_KEY"));

            var entries = await _ctLogAggregator.QueryAsync(fingerprint, cancellationToken).ConfigureAwait(false);
            _ctLogEntries.AddRange(entries);
            _ctDiscoverySources = _ctLogAggregator.LastQueriedSources
                .Where(source => !string.IsNullOrWhiteSpace(source))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            _ctTemplateFormatErrors = _ctLogAggregator.LastTemplateFormatErrors
                .Where(error => !string.IsNullOrWhiteSpace(error))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            PresentInCtLogs = _ctLogEntries.Count > 0;
        }

        private static string? FirstNonEmpty(string? explicitValue, string? fallbackValue) {
            if (!string.IsNullOrWhiteSpace(explicitValue)) {
                return explicitValue;
            }

            if (!string.IsNullOrWhiteSpace(fallbackValue)) {
                return fallbackValue;
            }

            return null;
        }

        /// <summary>
        /// Standalone version to check the website certificate.
        /// </summary>
        /// <param name="url">The URL. If no scheme is provided, "https://" will be prepended.</param>
        /// <param name="port">The port.</param>
        /// <param name="cancellationToken">Cancellation token to stop the operation.</param>
        /// <returns>The populated <see cref="CertificateAnalysis"/> instance.</returns>
        public static async Task<CertificateAnalysis> CheckWebsiteCertificate(string url, int port = 443, CancellationToken cancellationToken = default) {
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                url = $"https://{url}";
            }
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl(url, port, new InternalLogger(), cancellationToken);
            return analysis;
        }

        /// <summary>
        /// Checks certificates for multiple URLs concurrently.
        /// </summary>
        /// <param name="urls">The URLs. If no scheme is provided, "https://" will be prepended.</param>
        /// <param name="port">The port.</param>
        /// <param name="cancellationToken">Cancellation token to stop the operation.</param>
        /// <returns>List of populated <see cref="CertificateAnalysis"/> instances.</returns>
        public static async Task<IReadOnlyList<CertificateAnalysis>> CheckWebsiteCertificates(IEnumerable<string> urls, int port = 443, CancellationToken cancellationToken = default) {
            var tasks = urls.Select(u => CheckWebsiteCertificate(u, port, cancellationToken));
            return await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        /// <summary>
        /// Analyzes a provided certificate without performing any network operations.
        /// </summary>
        /// <param name="certificate">Certificate instance to inspect.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) {
            Certificate = CertificateLoaderCompat.Clone(certificate);
            IsSelfSigned = false;
            ResetChainSourceTracking();
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
            IsValid = chain.Build(certificate);
            Chain.Clear();
            foreach (var element in chain.ChainElements) {
                Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
            }
            RecordChainSource(SkipRevocation ? ChainSourceLocalBuildNoCheck : ChainSourceLocalBuildOnline);
            IsSelfSigned = IsSelfSignedCertificate(Certificate);
            PopulateKeyInfo();
            DaysToExpire = (int)(certificate.NotAfter - DateTime.Now).TotalDays;
            DaysValid = (int)(certificate.NotAfter - certificate.NotBefore).TotalDays;
            IsExpired = certificate.NotAfter < DateTime.Now;
            if (CaptureExtendedMetadata && !SkipRevocation) {
                await QueryRevocationEndpoints(cancellationToken);
            }
            PopulateSubjectAlternativeNames();
            if (CaptureExtendedMetadata || CaptureCtMetadata) {
                await QueryCtLogs(cancellationToken);
            }
        }

        private void EnsureChainBuilt(X509Certificate2 certificate) {
            if (Chain.Count > 1) {
                return;
            }

            if (TryBuildChain(certificate, SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online)) {
                return;
            }

            if (!SkipRevocation) {
                TryBuildChain(certificate, X509RevocationMode.NoCheck);
            }
        }

        private bool TryBuildChain(X509Certificate2 certificate, X509RevocationMode revocationMode) {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = revocationMode;
            chain.ChainPolicy.UrlRetrievalTimeout = Timeout;
            chain.Build(certificate);
            if (chain.ChainElements.Count <= Chain.Count) {
                return false;
            }

            Chain.Clear();
            foreach (var element in chain.ChainElements) {
                Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
            }
            RecordChainSource(revocationMode == X509RevocationMode.NoCheck ? ChainSourceLocalBuildNoCheck : ChainSourceLocalBuildOnline);
            return true;
        }

        private void ResetChainSourceTracking() {
            ChainSource = string.Empty;
            ChainSourceHistory.Clear();
        }

        private void RecordChainSource(string source) {
            if (string.IsNullOrWhiteSpace(source)) {
                return;
            }

            ChainSource = source;
            if (!ChainSourceHistory.Contains(source, StringComparer.OrdinalIgnoreCase)) {
                ChainSourceHistory.Add(source);
            }
        }

        private void PopulateSubjectAlternativeNames() {
            SubjectAlternativeNames.Clear();
            WildcardSubdomains.Clear();
            IsWildcardCertificate = false;
            SecuresUnrelatedHosts = false;

            if (Certificate == null) {
                return;
            }

            var parser = new X509CertificateParser();
            var bcCert = parser.ReadCertificate(Certificate.RawData);
            var sanExt = bcCert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (sanExt != null) {
                var names = GeneralNames.GetInstance(Asn1Object.FromByteArray(sanExt.GetOctets()));
                foreach (var gn in names.GetNames()) {
                    if (gn.TagNo == GeneralName.DnsName) {
                        var dns = DerIA5String.GetInstance(gn.Name).GetString();
                        SubjectAlternativeNames.Add(dns);
                    }
                }
            }

            var cn = Certificate.GetNameInfo(X509NameType.DnsName, false);
            if (!string.IsNullOrWhiteSpace(cn) && !SubjectAlternativeNames.Contains(cn)) {
                SubjectAlternativeNames.Add(cn);
            }

            var wildcards = new List<string>();
            foreach (var name in SubjectAlternativeNames) {
                if (name.StartsWith("*.", StringComparison.Ordinal)) {
                    wildcards.Add(name);
                }
            }

            foreach (var wc in wildcards) {
                var baseDomain = wc.Substring(2);
                var matches = new List<string>();
                foreach (var n in SubjectAlternativeNames) {
                    if (!n.Equals(wc, StringComparison.OrdinalIgnoreCase) && n.EndsWith('.' + baseDomain, StringComparison.OrdinalIgnoreCase)) {
                        if (!matches.Contains(n)) {
                            matches.Add(n);
                        }
                    }
                }
                WildcardSubdomains[wc] = matches;
            }

            IsWildcardCertificate = WildcardSubdomains.Count > 0;

            var baseDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in SubjectAlternativeNames) {
                var parts = name.Split('.');
                if (parts.Length >= 2) {
                    var baseDom = parts[parts.Length - 2] + "." + parts[parts.Length - 1];
                    baseDomains.Add(baseDom);
                } else {
                    baseDomains.Add(name);
                }
            }
            SecuresUnrelatedHosts = baseDomains.Count > 1 && SubjectAlternativeNames.Count > 5;
        }

    }
}
