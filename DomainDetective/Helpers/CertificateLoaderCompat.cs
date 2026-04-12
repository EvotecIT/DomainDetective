using System;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Helpers;

// Intentionally public: shared by the core library, CLI, and PowerShell assemblies.
/// <summary>Provides certificate loader compat functionality.</summary>
public static class CertificateLoaderCompat
{
    /// <summary>Loads certificate.</summary>
    public static X509Certificate2 LoadCertificate(byte[] rawData)
    {
        if (rawData == null)
        {
            throw new ArgumentNullException(nameof(rawData));
        }

#if NET10_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(rawData);
#else
        return new X509Certificate2(rawData);
#endif
    }

    /// <summary>Loads certificate from file.</summary>
    public static X509Certificate2 LoadCertificateFromFile(string path)
    {
        if (path == null)
        {
            throw new ArgumentNullException(nameof(path));
        }

#if NET10_0_OR_GREATER
        return X509CertificateLoader.LoadCertificateFromFile(path);
#else
        return new X509Certificate2(path);
#endif
    }

    /// <summary>Loads a PKCS#12/PFX certificate.</summary>
    public static X509Certificate2 LoadPkcs12(byte[] rawData)
    {
        if (rawData == null)
        {
            throw new ArgumentNullException(nameof(rawData));
        }

#if NET10_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(rawData, null, X509KeyStorageFlags.DefaultKeySet, null);
#else
        return new X509Certificate2(rawData);
#endif
    }

    /// <summary>Executes the clone operation.</summary>
    public static X509Certificate2 Clone(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        return LoadCertificate(certificate.RawData);
    }
}
