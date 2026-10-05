using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective;

public partial class CertificateAnalysis {
    private readonly List<X509Certificate2> _ownedCertificates = new();
    private bool _disposed;

    private X509Certificate2 OwnCertificate(X509Certificate2 certificate) {
        _ownedCertificates.Add(certificate);
        return certificate;
    }

    private void ResetObservedState() {
        if (_disposed) throw new ObjectDisposedException(nameof(CertificateAnalysis));
        foreach (var certificate in _ownedCertificates) certificate.Dispose();
        _ownedCertificates.Clear();
        Certificate = null;
        Chain.Clear();
        Subject = null;
        Url = string.Empty;
        IsValid = IsReachable = HostnameMatch = false;
        ChainValidationPerformed = HostnameValidationPerformed = ProvidedCertificateInspection = false;
        FailureReason = null;
        FailureKind = CertificateFailureKind.None;
        DaysToExpire = DaysValid = 0;
        IsExpired = IsSelfSigned = false;
        ProtocolVersion = null;
        Http2Supported = Http3Supported = false;
        RemoteAddress = null;
        RedirectTargets.Clear();
        ResetChainSourceTracking();
        OcspUrls.Clear();
        CrlUrls.Clear();
        OcspRevoked = CrlRevoked = null;
        SubjectAlternativeNames.Clear();
        WildcardSubdomains.Clear();
        IsWildcardCertificate = SecuresUnrelatedHosts = false;
        KeyAlgorithm = string.Empty;
        KeySize = 0;
        WeakKey = Sha1Signature = RsaPssSignature = false;
        HasEnhancedKeyUsageExtension = HasAnyExtendedKeyUsageOid = false;
        AllowsServerAuthentication = AllowsClientAuthentication = AllowsSecureEmail = false;
        ExtendedKeyUsageOids.Clear();
        ExtendedKeyUsageFriendlyNames.Clear();
        AuthenticationProfile = CertificateAuthenticationProfileClassifier.NoEkuExtension;
        TlsProtocol = SslProtocols.None;
        Tls13Used = false;
        CipherAlgorithm = CipherSuite = string.Empty;
        CipherStrength = DhKeyBits = 0;
        PresentInCtLogs = false;
        _ctLogEntries.Clear();
        _ctDiscoverySources = _ctTemplateFormatErrors = Array.Empty<string>();
        Assessments.Clear();
        GradeLevel = GradeLevel.Unknown;
        LegacyEnabled = SupportsTls10 = SupportsTls11 = SupportsTls12 = SupportsTls13 = false;
        SctCount = 0;
        OcspMustStaple = false;
        OcspStaplingPresent = null;
    }

    /// <summary>Releases certificates created by this analysis; externally supplied certificates remain caller-owned.</summary>
    public void Dispose() {
        if (_disposed) return;
        ResetObservedState();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
