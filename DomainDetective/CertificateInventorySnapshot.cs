using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace DomainDetective {
    /// <summary>
    /// Represents one persisted certificate inventory snapshot.
    /// </summary>
    public sealed class CertificateInventorySnapshot {
        public DateTimeOffset CapturedAtUtc { get; set; }
        public int Port { get; set; }
        public List<CertificateInventoryEntry> Entries { get; set; } = new();
    }

    /// <summary>
    /// Represents one host entry inside a certificate inventory snapshot.
    /// </summary>
    public sealed class CertificateInventoryEntry {
        public string Host { get; set; } = string.Empty;
        public string? ResolvedHost { get; set; }
        public string Url { get; set; } = string.Empty;
        public string Scheme { get; set; } = "https";
        public int Port { get; set; } = 443;
        public string Service { get; set; } = "HTTPS";
        public string? CertificateSubject { get; set; }
        public string? CertificateIssuer { get; set; }
        public string? CertificateThumbprint { get; set; }
        public string? CertificateSerialNumber { get; set; }
        public string? CertificateIssuerCommonName { get; set; }
        public string? CertificateIssuerOrganization { get; set; }
        public string? CertificateIssuerNormalized { get; set; }
        public string? CertificateAuthorityFamily { get; set; }
        public string? CertificateRootSubject { get; set; }
        public string? CertificateRootIssuer { get; set; }
        public string? CertificateRootIssuerCommonName { get; set; }
        public string? CertificateRootIssuerOrganization { get; set; }
        public string? CertificateRootIssuerNormalized { get; set; }
        public string? CertificateRootAuthorityFamily { get; set; }
        public string? CertificateRootThumbprint { get; set; }
        public int CertificateChainLength { get; set; }
        public int CertificateIntermediateCount { get; set; }
        public bool IsKnownCertificateAuthority { get; set; }
        public bool IsKnownRootCertificateAuthority { get; set; }
        public DateTimeOffset? NotBeforeUtc { get; set; }
        public DateTimeOffset? NotAfterUtc { get; set; }
        public bool Valid { get; set; }
        public bool Expired { get; set; }
        public bool ChainComplete { get; set; }
        public bool IsReachable { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool HostnameMatch { get; set; }
        public bool PresentInCtLogs { get; set; }
        /// <summary>CT/discovery sources queried when evaluating certificate presence.</summary>
        public List<string> CtDiscoverySources { get; set; } = new();
        /// <summary>Days to expiry as observed at snapshot capture time.</summary>
        public int DaysToExpire { get; set; }
        public int DaysValid { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string KeyAlgorithm { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public bool WeakKey { get; set; }
        public bool Sha1Signature { get; set; }
        public bool RsaPssSignature { get; set; }
        public bool HasEnhancedKeyUsageExtension { get; set; }
        public bool HasAnyExtendedKeyUsageOid { get; set; }

        [Obsolete("Use HasAnyExtendedKeyUsageOid.")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool HasAnyExtendedKeyUsage {
            get { return HasAnyExtendedKeyUsageOid; }
            set { HasAnyExtendedKeyUsageOid = value; }
        }

        public bool AllowsServerAuthentication { get; set; }
        public bool AllowsClientAuthentication { get; set; }
        public bool AllowsSecureEmail { get; set; }
        public string AuthenticationProfile { get; set; } = CertificateAuthenticationProfileClassifier.NoEkuExtension;
        public string? CertificateChainSource { get; set; }
        public List<string> CertificateChainSources { get; set; } = new();
        public List<string> ExtendedKeyUsageOids { get; set; } = new();
        public List<string> SubjectAlternativeNames { get; set; } = new();
        public List<string> CertificateChainSubjects { get; set; } = new();
        public List<string> CertificateChainIssuers { get; set; } = new();
        public List<string> CertificateChainThumbprints { get; set; } = new();
    }
}
