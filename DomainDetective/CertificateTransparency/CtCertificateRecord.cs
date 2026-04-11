using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Represents a normalized certificate transparency certificate record.
/// </summary>
public sealed class CtCertificateRecord
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";
    private static readonly char[] InvalidDnsNameCharacters = { ' ', '/', '@', ',' };

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

    /// <summary>Subject alternative DNS names and common name candidates observed on the certificate, sorted case-insensitively.</summary>
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

        // Keep the normalized record immutable even if the caller later mutates their input buffer.
        byte[] rawData = certificateDer.ToArray();
        using X509Certificate2 certificate = CertificateLoaderCompat.LoadCertificate(rawData);
        CertificateExtendedKeyUsageInfo eku = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);
        string? signatureOid = certificate.SignatureAlgorithm?.Value;
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
            WeakKey = IsWeakPublicKey(certificate),
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
        AddDnsNameIfCandidate(names, SafeGetNameInfo(certificate, X509NameType.DnsName));
        AddDnsNameIfCandidate(names, TryExtractCommonName(certificate.Subject));

        try
        {
            X509Extension? san = certificate.Extensions[SubjectAlternativeNameOid];
            if (san != null)
            {
#if NET8_0_OR_GREATER
                var sanExtension = new X509SubjectAlternativeNameExtension(san.RawData, san.Critical);
                foreach (string dnsName in sanExtension.EnumerateDnsNames())
                {
                    AddDnsNameIfCandidate(names, dnsName);
                }
#else
                int sanNameCount = 0;
                foreach (string dnsName in ParseDnsNamesFromSanExtension(san.RawData))
                {
                    sanNameCount++;
                    AddDnsNameIfCandidate(names, dnsName);
                }

                if (sanNameCount == 0)
                {
                    // Last-resort fallback for unusual pre-net8 certificates; the raw parser above avoids relying on localized Format() text in normal cases.
                    foreach (string dnsName in ParseDnsNamesFromSanText(san.Format(false)))
                    {
                        AddDnsNameIfCandidate(names, dnsName);
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

        foreach (string trimmed in SplitDistinguishedNameParts(subject!)
            .Select(part => part.Trim())
            .Where(part => part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)))
        {
            string value = UnescapeDistinguishedNameValue(trimmed.Substring(3).Trim());
            return value.Length == 0 ? null : value;
        }

        return null;
    }

    private static IEnumerable<string> SplitDistinguishedNameParts(string subject)
    {
        var builder = new StringBuilder();
        bool escaped = false;
        foreach (char character in subject)
        {
            if (escaped)
            {
                builder.Append('\\');
                builder.Append(character);
                escaped = false;
                continue;
            }

            if (character == '\\')
            {
                escaped = true;
                continue;
            }

            if (character == ',')
            {
                yield return builder.ToString();
                builder.Clear();
                continue;
            }

            builder.Append(character);
        }

        if (escaped)
        {
            builder.Append('\\');
        }

        yield return builder.ToString();
    }

    private static string UnescapeDistinguishedNameValue(string value)
    {
        var builder = new StringBuilder(value.Length);
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            if (character != '\\')
            {
                builder.Append(character);
                continue;
            }

            if (TryReadHexEscapedBytes(value, ref index, out string decodedValue))
            {
                builder.Append(decodedValue);
                continue;
            }

            if (index + 1 < value.Length)
            {
                builder.Append(value[++index]);
            }
            else
            {
                builder.Append('\\');
            }
        }

        return builder.ToString().Trim();
    }

    private static bool TryReadHexEscapedBytes(string value, ref int index, out string decodedValue)
    {
        decodedValue = string.Empty;
        if (index + 2 >= value.Length ||
            !Uri.IsHexDigit(value[index + 1]) ||
            !Uri.IsHexDigit(value[index + 2]))
        {
            return false;
        }

        var bytes = new List<byte>();
        int currentIndex = index;
        while (currentIndex + 2 < value.Length &&
               value[currentIndex] == '\\' &&
               Uri.IsHexDigit(value[currentIndex + 1]) &&
               Uri.IsHexDigit(value[currentIndex + 2]))
        {
            string hex = value.Substring(currentIndex + 1, 2);
            bytes.Add(Convert.ToByte(hex, 16));
            currentIndex += 3;
        }

        decodedValue = Encoding.UTF8.GetString(bytes.ToArray());
        index = currentIndex - 1;
        return true;
    }

    private static void AddDnsNameIfCandidate(HashSet<string> names, string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }

        string value = name!.Trim();
        string hostCandidate = value.StartsWith("*.", StringComparison.Ordinal)
            ? value.Substring(2)
            : value;
        if (hostCandidate.Length == 0 ||
            hostCandidate.IndexOfAny(InvalidDnsNameCharacters) >= 0 ||
            Uri.CheckHostName(hostCandidate) != UriHostNameType.Dns)
        {
            return;
        }

        names.Add(value);
    }

    private static string? NormalizeHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        char[] output = new char[value!.Length];
        int count = 0;
        foreach (char character in value.Where(IsHexDigit))
        {
            output[count++] = char.ToUpperInvariant(character);
        }

        return new string(output, 0, count);
    }

    private static bool IsSelfSignedCertificate(X509Certificate2 certificate)
    {
        return certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData);
    }

    private static bool IsSha1Signature(string? oid)
    {
        return oid == "1.2.840.113549.1.1.5" || // sha1WithRSAEncryption
               oid == "1.2.840.10040.4.3" ||    // id-dsa-with-sha1
               oid == "1.2.840.10045.4.1" ||    // ecdsa-with-SHA1
               oid == "1.3.14.3.2.29";          // legacy sha1WithRSA
    }

    private static bool IsHexDigit(char character)
    {
        bool isDecimalDigit = character >= '0' && character <= '9';
        bool isLowerHexLetter = character >= 'a' && character <= 'f';
        bool isUpperHexLetter = character >= 'A' && character <= 'F';
        return isDecimalDigit || isLowerHexLetter || isUpperHexLetter;
    }

    private static bool IsWeakPublicKey(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return false;
        }

        try
        {
            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                return rsa.KeySize < 2048;
            }
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
            // Some platform providers throw for unsupported key algorithms; fall through to the next algorithm probe.
        }

        try
        {
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return ecdsa.KeySize < 224;
            }
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
            // Some platform providers throw for unsupported key algorithms; fall through to the next algorithm probe.
        }

        try
        {
            using DSA? dsa = certificate.GetDSAPublicKey();
            if (dsa != null)
            {
                return dsa.KeySize < 2048;
            }
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
            // Some platform providers throw for unsupported key algorithms; treat unknown algorithms as not weak.
        }

        return false;
    }

    private static IEnumerable<string> ParseDnsNamesFromSanText(string? formattedSan)
    {
        if (string.IsNullOrWhiteSpace(formattedSan))
        {
            yield break;
        }

        foreach (string item in formattedSan!
            .Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Trim()))
        {
            const string dnsNamePrefix = "DNS Name=";
            const string dnsShortPrefix = "DNS:";

            if (item.StartsWith(dnsNamePrefix, StringComparison.OrdinalIgnoreCase))
            {
                string value = item.Substring(dnsNamePrefix.Length).Trim();
                if (value.Length > 0)
                {
                    yield return value;
                }
            }
            else if (item.StartsWith(dnsShortPrefix, StringComparison.OrdinalIgnoreCase))
            {
                string value = item.Substring(dnsShortPrefix.Length).Trim();
                if (value.Length > 0)
                {
                    yield return value;
                }
            }
        }
    }

    private static IEnumerable<string> ParseDnsNamesFromSanExtension(byte[] rawData)
    {
        if (rawData == null || rawData.Length == 0)
        {
            yield break;
        }

        int offset = 0;
        int sequenceLimit = rawData.Length;
        if (rawData[offset] == 0x04)
        {
            if (!TryReadTagAndLength(rawData, ref offset, expectedTag: 0x04, out int octetLength) ||
                offset + octetLength > rawData.Length)
            {
                yield break;
            }

            sequenceLimit = offset + octetLength;
        }

        if (!TryReadTagAndLength(rawData, ref offset, expectedTag: 0x30, out int sequenceLength))
        {
            yield break;
        }

        int sequenceEnd = offset + sequenceLength;
        if (sequenceEnd > sequenceLimit)
        {
            yield break;
        }

        while (offset < sequenceEnd)
        {
            byte tag = rawData[offset++];
            if (!TryReadAsnLength(rawData, ref offset, out int length) ||
                offset + length > sequenceEnd)
            {
                yield break;
            }

            if (tag == 0x82 && length > 0)
            {
                string value = Encoding.ASCII.GetString(rawData, offset, length).Trim();
                if (value.Length > 0)
                {
                    yield return value;
                }
            }

            offset += length;
        }
    }

    private static bool TryReadTagAndLength(byte[] data, ref int offset, byte expectedTag, out int length)
    {
        length = 0;
        if (data == null || offset < 0 || offset >= data.Length)
        {
            return false;
        }

        byte tag = data[offset++];
        if (tag != expectedTag)
        {
            return false;
        }

        return TryReadAsnLength(data, ref offset, out length);
    }

    private static bool TryReadAsnLength(byte[] data, ref int offset, out int length)
    {
        length = 0;
        if (data == null || offset < 0 || offset >= data.Length)
        {
            return false;
        }

        byte first = data[offset++];
        if ((first & 0x80) == 0)
        {
            length = first;
            return true;
        }

        int count = first & 0x7F;
        if (count <= 0 || count > 4 || offset + count > data.Length)
        {
            // Indefinite or unusually large ASN.1 lengths are treated as unsupported by this pre-net8 fallback parser.
            return false;
        }

        int value = 0;
        for (int i = 0; i < count; i++)
        {
            value = (value << 8) | data[offset++];
        }

        length = value;
        return true;
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
