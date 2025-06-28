using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective;

/// <summary>
/// Parses S/MIME certificates from files and exposes basic information.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class SmimeCertificateAnalysis {
    /// <summary>Gets the loaded certificate.</summary>
    public X509Certificate2 Certificate { get; private set; }

    /// <summary>Gets the certificate chain.</summary>
    public List<X509Certificate2> Chain { get; } = new();

    /// <summary>Gets a value indicating whether the certificate chain is valid.</summary>
    public bool IsValid { get; private set; }

    /// <summary>Gets the number of days until the certificate expires.</summary>
    public int DaysToExpire { get; private set; }

    /// <summary>Gets the total validity period in days.</summary>
    public int DaysValid { get; private set; }

    /// <summary>Gets a value indicating whether the certificate is expired.</summary>
    public bool IsExpired { get; private set; }

    /// <summary>
    /// Loads and analyses a certificate from <paramref name="path"/>.
    /// </summary>
    /// <param name="path">Path to the certificate file in DER or PEM format.</param>
    public void AnalyzeFile(string path) {
        if (!File.Exists(path)) {
            throw new FileNotFoundException("Certificate file not found", path);
        }

        byte[] data;
        try {
            data = File.ReadAllBytes(path);
            Certificate = new X509Certificate2(data);
        } catch (CryptographicException) {
            var text = File.ReadAllText(path);
            data = DecodePem(text);
            Certificate = new X509Certificate2(data);
        }

        var chain = new X509Chain();
        IsValid = chain.Build(Certificate);
        Chain.Clear();
        foreach (var element in chain.ChainElements) {
            Chain.Add(new X509Certificate2(element.Certificate.RawData));
        }

        DaysToExpire = (int)(Certificate.NotAfter - DateTime.Now).TotalDays;
        DaysValid = (int)(Certificate.NotAfter - Certificate.NotBefore).TotalDays;
        IsExpired = Certificate.NotAfter < DateTime.Now;
    }

    private static byte[] DecodePem(string pem) {
        const string header = "-----BEGIN CERTIFICATE-----";
        const string footer = "-----END CERTIFICATE-----";
        var start = pem.IndexOf(header, StringComparison.Ordinal);
        if (start >= 0) {
            start += header.Length;
            var end = pem.IndexOf(footer, start, StringComparison.Ordinal);
            if (end >= 0) {
                pem = pem.Substring(start, end - start);
            }
        }
        pem = pem.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
        return Convert.FromBase64String(pem);
    }
}
