using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective {
    /// <summary>
    /// Provides parsed Extended Key Usage information for an X.509 certificate.
    /// </summary>
    public sealed class CertificateExtendedKeyUsageInfo {
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
        public List<string> Oids { get; } = new();
        public List<string> FriendlyNames { get; } = new();
    }

    /// <summary>
    /// Normalizes EKU flags into a stable authentication profile name.
    /// </summary>
    public static class CertificateAuthenticationProfileClassifier {
        public const string NoEkuExtension = "NoEkuExtension";
        public const string EkuPresentNoUsages = "EkuPresentNoUsages";
        public const string AnyExtendedKeyUsage = "AnyExtendedKeyUsage";
        public const string ServerAuthOnly = "ServerAuthOnly";
        public const string ClientAuthOnly = "ClientAuthOnly";
        public const string ServerAndClientAuth = "ServerAndClientAuth";
        public const string SecureEmailOnly = "SecureEmailOnly";
        public const string MixedOrCustom = "MixedOrCustom";

        public static string Classify(CertificateExtendedKeyUsageInfo? info) {
            if (info == null) {
                return NoEkuExtension;
            }

            return Classify(
                info.HasEnhancedKeyUsageExtension,
                info.HasAnyExtendedKeyUsageOid,
                info.AllowsServerAuthentication,
                info.AllowsClientAuthentication,
                info.AllowsSecureEmail,
                info.Oids);
        }

        public static string Classify(
            bool hasEnhancedKeyUsageExtension,
            bool hasAnyExtendedKeyUsageOid,
            bool allowsServerAuthentication,
            bool allowsClientAuthentication,
            bool allowsSecureEmail,
            IReadOnlyCollection<string>? oids = null) {
            if (!hasEnhancedKeyUsageExtension) {
                return NoEkuExtension;
            }

            if (hasAnyExtendedKeyUsageOid) {
                return AnyExtendedKeyUsage;
            }

            if (allowsServerAuthentication && allowsClientAuthentication && !allowsSecureEmail) {
                return ServerAndClientAuth;
            }

            if (allowsServerAuthentication && !allowsClientAuthentication && !allowsSecureEmail) {
                return ServerAuthOnly;
            }

            if (!allowsServerAuthentication && allowsClientAuthentication && !allowsSecureEmail) {
                return ClientAuthOnly;
            }

            if (!allowsServerAuthentication && !allowsClientAuthentication && allowsSecureEmail) {
                return SecureEmailOnly;
            }

            var oidCount = oids?.Count ?? 0;
            if (oidCount == 0) {
                return EkuPresentNoUsages;
            }

            return MixedOrCustom;
        }
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
            foreach (var extension in ekuExtensions) {
                OidCollection usages;
                try {
                    usages = extension.EnhancedKeyUsages;
                } catch (CryptographicException) {
                    continue;
                }

                foreach (var oid in usages.Cast<Oid>()) {
                    if (string.IsNullOrWhiteSpace(oid.Value)) {
                        continue;
                    }

                    if (seen.Add(oid.Value)) {
                        result.Oids.Add(oid.Value);
                    }
                }
            }

            result.HasAnyExtendedKeyUsageOid = result.Oids.Contains(AnyExtendedKeyUsageOid, StringComparer.Ordinal);
            result.AllowsServerAuthentication = result.HasAnyExtendedKeyUsageOid || result.Oids.Contains(ServerAuthenticationOid, StringComparer.Ordinal);
            result.AllowsClientAuthentication = result.HasAnyExtendedKeyUsageOid || result.Oids.Contains(ClientAuthenticationOid, StringComparer.Ordinal);
            result.AllowsSecureEmail = result.HasAnyExtendedKeyUsageOid || result.Oids.Contains(SecureEmailOid, StringComparer.Ordinal);
            result.AuthenticationProfile = CertificateAuthenticationProfileClassifier.Classify(result);

            foreach (var oid in result.Oids) {
                if (KnownFriendlyNames.TryGetValue(oid, out var knownName)) {
                    result.FriendlyNames.Add(knownName);
                    continue;
                }

                try {
                    result.FriendlyNames.Add(new Oid(oid).FriendlyName ?? oid);
                } catch (CryptographicException) {
                    result.FriendlyNames.Add(oid);
                }
            }

            return result;
        }
    }
}
