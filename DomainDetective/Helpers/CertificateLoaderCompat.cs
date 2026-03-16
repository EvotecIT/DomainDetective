using System;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Helpers;

internal static class CertificateLoaderCompat
{
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

    public static X509Certificate2 Clone(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        return LoadCertificate(certificate.RawData);
    }
}
