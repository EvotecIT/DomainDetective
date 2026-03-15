using System;
using System.Net.Security;
using System.Security.Authentication;

namespace DomainDetective.Helpers;

internal sealed class TlsNegotiationInfo
{
    public string CipherAlgorithm { get; init; } = string.Empty;
    public int CipherStrength { get; init; }
    public string CipherSuite { get; init; } = string.Empty;
    public int DhKeyBits { get; init; }
    public string KeyExchangeAlgorithm { get; init; } = string.Empty;
    public int? KeyExchangeStrength { get; init; }
    public string HashAlgorithm { get; init; } = string.Empty;
    public int? HashStrength { get; init; }
}

internal static class TlsNegotiationInfoFactory
{
    public static TlsNegotiationInfo Create(SslStream ssl)
    {
        if (ssl == null)
        {
            throw new ArgumentNullException(nameof(ssl));
        }

#if NET10_0_OR_GREATER
        var cipherSuite = ssl.NegotiatedCipherSuite.ToString();
        return CreateFromCipherSuite(cipherSuite);
#else
        var keyExchangeAlgorithm = ssl.KeyExchangeAlgorithm.ToString();
        var keyExchangeStrength = ssl.KeyExchangeStrength;
        return new TlsNegotiationInfo
        {
            CipherAlgorithm = ssl.CipherAlgorithm.ToString(),
            CipherStrength = ssl.CipherStrength,
#if NET8_0_OR_GREATER
            CipherSuite = ssl.NegotiatedCipherSuite.ToString(),
#endif
            DhKeyBits = ssl.KeyExchangeAlgorithm == ExchangeAlgorithmType.DiffieHellman ? keyExchangeStrength : 0,
            KeyExchangeAlgorithm = keyExchangeAlgorithm,
            KeyExchangeStrength = keyExchangeStrength,
            HashAlgorithm = ssl.HashAlgorithm.ToString(),
            HashStrength = ssl.HashStrength
        };
#endif
    }

#if NET10_0_OR_GREATER
    private static TlsNegotiationInfo CreateFromCipherSuite(string cipherSuite)
    {
        return new TlsNegotiationInfo
        {
            CipherAlgorithm = DeriveCipherAlgorithm(cipherSuite),
            CipherStrength = DeriveCipherStrength(cipherSuite),
            CipherSuite = cipherSuite,
            DhKeyBits = 0,
            KeyExchangeAlgorithm = DeriveKeyExchangeAlgorithm(cipherSuite),
            KeyExchangeStrength = null,
            HashAlgorithm = DeriveHashAlgorithm(cipherSuite),
            HashStrength = DeriveHashStrength(cipherSuite)
        };
    }

    private static string DeriveCipherAlgorithm(string cipherSuite)
    {
        if (cipherSuite.IndexOf("CHACHA20", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "CHACHA20-POLY1305";
        }
        if (cipherSuite.IndexOf("AES", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "AES";
        }
        if (cipherSuite.IndexOf("CAMELLIA", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "CAMELLIA";
        }
        if (cipherSuite.IndexOf("ARIA", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "ARIA";
        }
        if (cipherSuite.IndexOf("3DES", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "3DES";
        }
        if (cipherSuite.IndexOf("RC4", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "RC4";
        }
        if (cipherSuite.IndexOf("NULL", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "NULL";
        }

        return string.Empty;
    }

    private static int DeriveCipherStrength(string cipherSuite)
    {
        if (cipherSuite.IndexOf("_256_", StringComparison.OrdinalIgnoreCase) >= 0 || cipherSuite.IndexOf("CHACHA20", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 256;
        }
        if (cipherSuite.IndexOf("_168_", StringComparison.OrdinalIgnoreCase) >= 0 || cipherSuite.IndexOf("3DES", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 168;
        }
        if (cipherSuite.IndexOf("_128_", StringComparison.OrdinalIgnoreCase) >= 0 || cipherSuite.IndexOf("RC4", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 128;
        }
        if (cipherSuite.IndexOf("_112_", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 112;
        }
        if (cipherSuite.IndexOf("_56_", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 56;
        }
        if (cipherSuite.IndexOf("_40_", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 40;
        }

        return 0;
    }

    private static string DeriveKeyExchangeAlgorithm(string cipherSuite)
    {
        if (string.IsNullOrWhiteSpace(cipherSuite))
        {
            return string.Empty;
        }

        if (cipherSuite.IndexOf("_WITH_", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            var start = cipherSuite.StartsWith("TLS_", StringComparison.OrdinalIgnoreCase) ? 4 : 0;
            var length = cipherSuite.IndexOf("_WITH_", StringComparison.OrdinalIgnoreCase) - start;
            if (length > 0)
            {
                return cipherSuite.Substring(start, length);
            }
        }

        if (cipherSuite.StartsWith("TLS_", StringComparison.OrdinalIgnoreCase))
        {
            return "TLS 1.3";
        }

        return string.Empty;
    }

    private static string DeriveHashAlgorithm(string cipherSuite)
    {
        if (cipherSuite.IndexOf("SHA512", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "SHA512";
        }
        if (cipherSuite.IndexOf("SHA384", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "SHA384";
        }
        if (cipherSuite.IndexOf("SHA256", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "SHA256";
        }
        if (cipherSuite.IndexOf("SHA", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "SHA1";
        }
        if (cipherSuite.IndexOf("MD5", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "MD5";
        }

        return string.Empty;
    }

    private static int? DeriveHashStrength(string cipherSuite)
    {
        if (cipherSuite.IndexOf("SHA512", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 512;
        }
        if (cipherSuite.IndexOf("SHA384", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 384;
        }
        if (cipherSuite.IndexOf("SHA256", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 256;
        }
        if (cipherSuite.IndexOf("SHA", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 160;
        }
        if (cipherSuite.IndexOf("MD5", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return 128;
        }

        return null;
    }
#endif
}
