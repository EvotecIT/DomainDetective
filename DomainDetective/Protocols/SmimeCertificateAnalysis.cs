using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

    /// <summary>Gets a value indicating whether the certificate chain is valid and trusted.</summary>
    public bool IsValid { get; private set; }

    /// <summary>Gets a value indicating whether the certificate chain is rooted in a trusted store.</summary>
    public bool IsTrustedRoot { get; private set; }

    /// <summary>Gets a value indicating whether the certificate includes the Secure Email EKU.</summary>
    public bool HasSecureEmailEku { get; private set; }

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
        path = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
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

        var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck } };
        var chainValid = chain.Build(Certificate);
        IsTrustedRoot = !chain.ChainStatus.Any(s => s.Status == X509ChainStatusFlags.UntrustedRoot);
        HasSecureEmailEku = Certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(e => e.EnhancedKeyUsages.Cast<Oid>())
            .Any(o => o.Value == "1.3.6.1.5.5.7.3.4");
        IsValid = chainValid && HasSecureEmailEku && IsTrustedRoot;
        Chain.Clear();
        foreach (var element in chain.ChainElements) {
            Chain.Add(new X509Certificate2(element.Certificate.RawData));
        }

        DaysToExpire = (int)(Certificate.NotAfter - DateTime.Now).TotalDays;
        DaysValid = (int)(Certificate.NotAfter - Certificate.NotBefore).TotalDays;
        IsExpired = Certificate.NotAfter < DateTime.Now;
    }

    /// <summary>
    /// Loads a certificate from directory and file name using <see cref="Path.Combine(string, string)"/>.
    /// </summary>
    /// <param name="directory">Directory containing the certificate.</param>
    /// <param name="fileName">Certificate file name.</param>
    public void AnalyzeFile(string directory, string fileName) {
        if (directory == null) {
            throw new ArgumentNullException(nameof(directory));
        }

        if (fileName == null) {
            throw new ArgumentNullException(nameof(fileName));
        }

        directory = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullPath = Path.Combine(directory, fileName);
        AnalyzeFile(fullPath);
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
