using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Represents a normalized certificate transparency certificate record.
/// </summary>
public sealed class CtCertificateRecord
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";

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

    /// <summary>True when the certificate subject and issuer match.</summary>
    public bool? IsSelfSigned { get; init; }

    /// <summary>True when the public key is considered weak for modern TLS use.</summary>
    public bool? WeakKey { get; init; }

    /// <summary>True when the certificate signature algorithm uses SHA-1.</summary>
    public bool? Sha1Signature { get; init; }

    /// <summary>True when the certificate can be used for TLS server authentication.</summary>
    public bool? AllowsServerAuthentication { get; init; }

    /// <summary>True when the certificate can be used for TLS client authentication.</summary>
    public bool? AllowsClientAuthentication { get; init; }

    /// <summary>True when the certificate can be used for secure email.</summary>
    public bool? AllowsSecureEmail { get; init; }

    /// <summary>Normalized authentication profile derived from Extended Key Usage.</summary>
    public string? AuthenticationProfile { get; init; }

    /// <summary>DER-encoded X.509 certificate or precertificate bytes.</summary>
    public byte[]? CertificateDer { get; init; }

    /// <summary>PEM-encoded certificate text, when supplied or derived by a provider.</summary>
    public string? CertificatePem { get; init; }

    /// <summary>True when the record is known to represent a precertificate.</summary>
    public bool? IsPrecertificate { get; init; }

    /// <summary>True when the record contains full certificate material.</summary>
    public bool HasFullCertificate => (CertificateDer != null && CertificateDer.Length > 0) ||
                                      !string.IsNullOrWhiteSpace(CertificatePem);

    /// <summary>
    /// Creates a CT certificate record from DER-encoded certificate bytes.
    /// </summary>
    /// <param name="providerId">Provider that supplied the certificate.</param>
    /// <param name="certificateDer">DER-encoded certificate bytes.</param>
    /// <param name="providerCertificateId">Optional provider-specific certificate identifier.</param>
    /// <param name="entryTimestampUtc">Optional CT entry timestamp.</param>
    /// <param name="tbsSha256">Optional provider-supplied TBS certificate SHA-256 value.</param>
    /// <param name="isPrecertificate">True when the provider reports a precertificate.</param>
    public static CtCertificateRecord FromDer(
        string providerId,
        byte[] certificateDer,
        string? providerCertificateId = null,
        DateTimeOffset? entryTimestampUtc = null,
        string? tbsSha256 = null,
        bool? isPrecertificate = null)
    {
        if (certificateDer == null)
        {
            throw new ArgumentNullException(nameof(certificateDer));
        }

        if (certificateDer.Length == 0)
        {
            throw new ArgumentException("Certificate DER bytes cannot be empty.", nameof(certificateDer));
        }

        byte[] rawData = certificateDer.ToArray();
        using X509Certificate2 certificate = CertificateLoaderCompat.LoadCertificate(rawData);
        CertificateExtendedKeyUsageInfo eku = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);
        string? signatureOid = certificate.SignatureAlgorithm?.Value;
        int keySize = GetPublicKeySize(certificate);
        byte[] sha256Bytes;
        using (SHA256 sha256 = SHA256.Create())
        {
            sha256Bytes = sha256.ComputeHash(rawData);
        }

        return new CtCertificateRecord
        {
            ProviderId = providerId ?? string.Empty,
            ProviderCertificateId = providerCertificateId,
            EntryTimestampUtc = entryTimestampUtc,
            Sha256Fingerprint = ToHex(sha256Bytes),
            Sha1Fingerprint = NormalizeHex(certificate.Thumbprint),
            TbsSha256 = NormalizeHex(tbsSha256),
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            SerialNumber = certificate.SerialNumber,
            NotBeforeUtc = new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
            NotAfterUtc = new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
            DnsNames = ExtractDnsNames(certificate),
            IsSelfSigned = IsSelfSignedCertificate(certificate),
            WeakKey = keySize > 0 && keySize < 2048,
            Sha1Signature = IsSha1Signature(signatureOid),
            AllowsServerAuthentication = eku.AllowsServerAuthentication,
            AllowsClientAuthentication = eku.AllowsClientAuthentication,
            AllowsSecureEmail = eku.AllowsSecureEmail,
            AuthenticationProfile = string.IsNullOrWhiteSpace(eku.AuthenticationProfile)
                ? CertificateAuthenticationProfileClassifier.Classify(eku)
                : eku.AuthenticationProfile,
            CertificateDer = rawData,
            IsPrecertificate = isPrecertificate
        };
    }

    private static IReadOnlyList<string> ExtractDnsNames(X509Certificate2 certificate)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddIfNotEmpty(names, SafeGetNameInfo(certificate, X509NameType.DnsName));
        AddIfNotEmpty(names, SafeGetNameInfo(certificate, X509NameType.SimpleName));
        AddIfNotEmpty(names, TryExtractCommonName(certificate.Subject));

        try
        {
            X509Extension? san = certificate.Extensions[SubjectAlternativeNameOid];
            if (san != null)
            {
#if NET8_0_OR_GREATER
                var sanExtension = new X509SubjectAlternativeNameExtension(san.RawData, san.Critical);
                foreach (string dnsName in sanExtension.EnumerateDnsNames())
                {
                    AddIfNotEmpty(names, dnsName);
                }
#else
                string formatted = san.Format(false);
                foreach (string part in formatted.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string item = part.Trim();
                    int equalsIndex = item.IndexOf('=');
                    if (equalsIndex <= 0)
                    {
                        continue;
                    }

                    string key = item.Substring(0, equalsIndex).Trim();
                    if (key.Equals("DNS Name", StringComparison.OrdinalIgnoreCase) ||
                        key.Equals("DNS", StringComparison.OrdinalIgnoreCase))
                    {
                        AddIfNotEmpty(names, item.Substring(equalsIndex + 1).Trim());
                    }
                }
#endif
            }
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
            // Keep certificate parsing resilient; callers still receive core certificate fields.
        }

        return names
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? SafeGetNameInfo(X509Certificate2 certificate, X509NameType type)
    {
        try
        {
            return certificate.GetNameInfo(type, false);
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
            return null;
        }
    }

    private static string? TryExtractCommonName(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return null;
        }

        foreach (string part in subject!.Split(','))
        {
            string trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                string value = trimmed.Substring(3).Trim();
                return value.Length == 0 ? null : value;
            }
        }

        return null;
    }

    private static void AddIfNotEmpty(HashSet<string> names, string? name)
    {
        if (!string.IsNullOrWhiteSpace(name))
        {
            names.Add(name!.Trim());
        }
    }

    private static string? NormalizeHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return new string(value!.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
    }

    private static bool IsSelfSignedCertificate(X509Certificate2 certificate)
    {
        return !string.IsNullOrWhiteSpace(certificate.Subject) &&
               string.Equals(certificate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSha1Signature(string? oid)
    {
        return oid == "1.2.840.113549.1.1.5" ||
               oid == "1.2.840.10040.4.3" ||
               oid == "1.3.14.3.2.29";
    }

    private static int GetPublicKeySize(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return 0;
        }

        try
        {
            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                return rsa.KeySize;
            }
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
        }

        try
        {
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return ecdsa.KeySize;
            }
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
        }

        try
        {
            using DSA? dsa = certificate.GetDSAPublicKey();
            if (dsa != null)
            {
                return dsa.KeySize;
            }
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
        }

        return 0;
    }

    private static string ToHex(byte[] bytes)
    {
        char[] output = new char[bytes.Length * 2];
        const string alphabet = "0123456789ABCDEF";
        for (int i = 0; i < bytes.Length; i++)
        {
            output[i * 2] = alphabet[bytes[i] >> 4];
            output[(i * 2) + 1] = alphabet[bytes[i] & 0x0F];
        }

        return new string(output);
    }
}
