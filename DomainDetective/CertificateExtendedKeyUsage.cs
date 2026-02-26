using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective {
    /// <summary>
    /// Provides parsed Extended Key Usage information for an X.509 certificate.
    /// </summary>
    public sealed class CertificateExtendedKeyUsageInfo {
        public bool HasEnhancedKeyUsageExtension { get; set; }
        public bool HasAnyExtendedKeyUsage { get; set; }
        public bool AllowsServerAuthentication { get; set; }
        public bool AllowsClientAuthentication { get; set; }
        public bool AllowsSecureEmail { get; set; }
        public List<string> Oids { get; } = new();
        public List<string> FriendlyNames { get; } = new();
    }

    /// <summary>
    /// Parses Extended Key Usage values from X.509 certificates.
    /// </summary>
    public static class CertificateExtendedKeyUsageAnalyzer {
        public const string AnyExtendedKeyUsageOid = "2.5.29.37.0";
        public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
        public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
        public const string SecureEmailOid = "1.3.6.1.5.5.7.3.4";

        private static readonly Dictionary<string, string> KnownFriendlyNames = new(StringComparer.Ordinal) {
            [AnyExtendedKeyUsageOid] = "Any Extended Key Usage",
            [ServerAuthenticationOid] = "Server Authentication",
            [ClientAuthenticationOid] = "Client Authentication",
            [SecureEmailOid] = "Secure Email"
        };

        public static CertificateExtendedKeyUsageInfo Analyze(X509Certificate2? certificate) {
            var result = new CertificateExtendedKeyUsageInfo();
            if (certificate == null) {
                return result;
            }

            var ekuExtensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToList();
            if (ekuExtensions.Count == 0) {
                return result;
            }

            result.HasEnhancedKeyUsageExtension = true;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var oid in ekuExtensions.SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())) {
                if (string.IsNullOrWhiteSpace(oid.Value)) {
                    continue;
                }

                if (seen.Add(oid.Value)) {
                    result.Oids.Add(oid.Value);
                }
            }

            result.HasAnyExtendedKeyUsage = result.Oids.Contains(AnyExtendedKeyUsageOid, StringComparer.Ordinal);
            result.AllowsServerAuthentication = result.HasAnyExtendedKeyUsage || result.Oids.Contains(ServerAuthenticationOid, StringComparer.Ordinal);
            result.AllowsClientAuthentication = result.HasAnyExtendedKeyUsage || result.Oids.Contains(ClientAuthenticationOid, StringComparer.Ordinal);
            result.AllowsSecureEmail = result.HasAnyExtendedKeyUsage || result.Oids.Contains(SecureEmailOid, StringComparer.Ordinal);

            foreach (var oid in result.Oids) {
                if (KnownFriendlyNames.TryGetValue(oid, out var knownName)) {
                    result.FriendlyNames.Add(knownName);
                    continue;
                }

                try {
                    result.FriendlyNames.Add(new Oid(oid).FriendlyName ?? oid);
                } catch {
                    result.FriendlyNames.Add(oid);
                }
            }

            return result;
        }
    }
}
