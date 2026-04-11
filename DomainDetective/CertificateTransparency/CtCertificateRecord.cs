using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Represents a normalized certificate transparency certificate record.
/// </summary>
public sealed class CtCertificateRecord
{
    /// <summary>Provider that returned the record.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Provider-specific certificate or issuance identifier.</summary>
    public string? ProviderCertificateId { get; init; }

    /// <summary>CT entry timestamp, when supplied by the provider.</summary>
    public DateTimeOffset? EntryTimestampUtc { get; init; }

    /// <summary>SHA-256 fingerprint of the DER certificate or precertificate.</summary>
    public string? Sha256Fingerprint { get; init; }

    /// <summary>SHA-1 fingerprint of the DER certificate or precertificate.</summary>
    public string? Sha1Fingerprint { get; init; }

    /// <summary>TBS certificate SHA-256 value when supplied by the provider.</summary>
    public string? TbsSha256 { get; init; }

    /// <summary>Subject distinguished name.</summary>
    public string? Subject { get; init; }

    /// <summary>Issuer distinguished name or provider-normalized issuer name.</summary>
    public string? Issuer { get; init; }

    /// <summary>Certificate serial number.</summary>
    public string? SerialNumber { get; init; }

    /// <summary>Certificate not-before timestamp.</summary>
    public DateTimeOffset? NotBeforeUtc { get; init; }

    /// <summary>Certificate not-after timestamp.</summary>
    public DateTimeOffset? NotAfterUtc { get; init; }

    /// <summary>Subject alternative DNS names and common name candidates observed on the certificate.</summary>
    public IReadOnlyList<string> DnsNames { get; init; } = Array.Empty<string>();

    /// <summary>DER-encoded X.509 certificate or precertificate bytes.</summary>
    public byte[]? CertificateDer { get; init; }

    /// <summary>PEM-encoded certificate text, when supplied or derived by a provider.</summary>
    public string? CertificatePem { get; init; }

    /// <summary>True when the record is known to represent a precertificate.</summary>
    public bool? IsPrecertificate { get; init; }

    /// <summary>True when the record contains full certificate material.</summary>
    public bool HasFullCertificate => (CertificateDer != null && CertificateDer.Length > 0) ||
                                      !string.IsNullOrWhiteSpace(CertificatePem);
}
