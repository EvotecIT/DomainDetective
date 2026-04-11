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
        /// <summary>Gets or sets the has enhanced key usage extension value.</summary>
        public bool HasEnhancedKeyUsageExtension { get; set; }
        /// <summary>Gets or sets the has any extended key usage oid value.</summary>
        public bool HasAnyExtendedKeyUsageOid { get; set; }

        /// <summary>Represents the has any extended key usage value.</summary>
        [Obsolete("Use HasAnyExtendedKeyUsageOid.")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool HasAnyExtendedKeyUsage {
            get { return HasAnyExtendedKeyUsageOid; }
            set { HasAnyExtendedKeyUsageOid = value; }
        }

        /// <summary>Gets or sets the allows server authentication value.</summary>
        public bool AllowsServerAuthentication { get; set; }
        /// <summary>Gets or sets the allows client authentication value.</summary>
        public bool AllowsClientAuthentication { get; set; }
        /// <summary>Gets or sets the allows secure email value.</summary>
        public bool AllowsSecureEmail { get; set; }
        /// <summary>Gets or sets the authentication profile value.</summary>
        public string AuthenticationProfile { get; set; } = CertificateAuthenticationProfileClassifier.NoEkuExtension;
        /// <summary>Gets the oids value.</summary>
        public List<string> Oids { get; } = new();
        /// <summary>Gets the friendly names value.</summary>
        public List<string> FriendlyNames { get; } = new();
    }

    /// <summary>
    /// Normalizes EKU flags into a stable authentication profile name.
    /// </summary>
    public static class CertificateAuthenticationProfileClassifier {
        /// <summary>Represents the no eku extension value.</summary>
        public const string NoEkuExtension = "NoEkuExtension";
        /// <summary>Represents the eku present no usages value.</summary>
        public const string EkuPresentNoUsages = "EkuPresentNoUsages";
        /// <summary>Represents the any extended key usage value.</summary>
        public const string AnyExtendedKeyUsage = "AnyExtendedKeyUsage";
        /// <summary>Represents the server auth only value.</summary>
        public const string ServerAuthOnly = "ServerAuthOnly";
        /// <summary>Represents the client auth only value.</summary>
        public const string ClientAuthOnly = "ClientAuthOnly";
        /// <summary>Represents the server and client auth value.</summary>
        public const string ServerAndClientAuth = "ServerAndClientAuth";
        /// <summary>Represents the secure email only value.</summary>
        public const string SecureEmailOnly = "SecureEmailOnly";
        /// <summary>Represents the mixed or custom value.</summary>
        public const string MixedOrCustom = "MixedOrCustom";

        /// <summary>Executes the classify operation.</summary>
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

        /// <summary>Executes the classify operation.</summary>
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
        /// <summary>Represents the any extended key usage oid value.</summary>
        public const string AnyExtendedKeyUsageOid = "2.5.29.37.0";
        /// <summary>Represents the server authentication oid value.</summary>
        public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
        /// <summary>Represents the client authentication oid value.</summary>
        public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
        /// <summary>Represents the secure email oid value.</summary>
        public const string SecureEmailOid = "1.3.6.1.5.5.7.3.4";

        private static readonly Dictionary<string, string> KnownFriendlyNames = new(StringComparer.Ordinal) {
            [AnyExtendedKeyUsageOid] = "Any Extended Key Usage",
            [ServerAuthenticationOid] = "Server Authentication",
            [ClientAuthenticationOid] = "Client Authentication",
            [SecureEmailOid] = "Secure Email"
        };

        /// <summary>Executes the analyze operation.</summary>
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
