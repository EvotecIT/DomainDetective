using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective {
    /// <summary>
    /// Structured issuer identity details derived from certificate issuer metadata.
    /// </summary>
    public sealed class CertificateIssuerIdentity {
        public string RawIssuer { get; set; } = string.Empty;
        public string? Organization { get; set; }
        public string? CommonName { get; set; }
        public string NormalizedName { get; set; } = string.Empty;
        public string? AuthorityFamily { get; set; }
        public bool IsKnownAuthority { get; set; }
    }

    /// <summary>
    /// Maps issuer distinguished names to normalized CA authority names.
    /// </summary>
    public static class CertificateIssuerClassifier {
        private sealed class IssuerRule {
            public string AuthorityFamily { get; init; } = string.Empty;
            public string NormalizedName { get; init; } = string.Empty;
            public string[] Tokens { get; init; } = Array.Empty<string>();
        }

        private static readonly IssuerRule[] Rules = {
            new() { AuthorityFamily = "LetsEncrypt", NormalizedName = "Let's Encrypt", Tokens = new[] { "let's encrypt", "lets encrypt", "isrg", "acme", "r3", "e1", "e5" } },
            new() { AuthorityFamily = "DigiCert", NormalizedName = "DigiCert", Tokens = new[] { "digicert" } },
            new() { AuthorityFamily = "Sectigo", NormalizedName = "Sectigo", Tokens = new[] { "sectigo", "comodo", "comodoca" } },
            new() { AuthorityFamily = "GlobalSign", NormalizedName = "GlobalSign", Tokens = new[] { "globalsign" } },
            new() { AuthorityFamily = "GoogleTrustServices", NormalizedName = "Google Trust Services", Tokens = new[] { "google trust services", "gts" } },
            new() { AuthorityFamily = "AmazonTrustServices", NormalizedName = "Amazon Trust Services", Tokens = new[] { "amazon trust services", "amazon rsa", "amazon root" } },
            new() { AuthorityFamily = "Cloudflare", NormalizedName = "Cloudflare", Tokens = new[] { "cloudflare" } },
            new() { AuthorityFamily = "Microsoft", NormalizedName = "Microsoft", Tokens = new[] { "microsoft" } },
            new() { AuthorityFamily = "GoDaddy", NormalizedName = "GoDaddy", Tokens = new[] { "godaddy", "starfield" } },
            new() { AuthorityFamily = "ZeroSsl", NormalizedName = "ZeroSSL", Tokens = new[] { "zerossl" } },
            new() { AuthorityFamily = "Buypass", NormalizedName = "Buypass", Tokens = new[] { "buypass" } },
            new() { AuthorityFamily = "Entrust", NormalizedName = "Entrust", Tokens = new[] { "entrust" } },
            new() { AuthorityFamily = "SslDotCom", NormalizedName = "SSL.com", Tokens = new[] { "ssl.com" } }
        };

        public static CertificateIssuerIdentity Classify(X509Certificate2? certificate) {
            return Classify(certificate?.Issuer);
        }

        public static CertificateIssuerIdentity Classify(string? issuerDistinguishedName) {
            var rawIssuer = (issuerDistinguishedName ?? string.Empty).Trim();
            var organization = ExtractDistinguishedNameField(rawIssuer, "O");
            var commonName = ExtractDistinguishedNameField(rawIssuer, "CN");
            var haystack = $"{organization} {commonName} {rawIssuer}".ToLowerInvariant();
            foreach (var rule in Rules) {
                foreach (var token in rule.Tokens) {
                    if (haystack.IndexOf(token, StringComparison.Ordinal) >= 0) {
                        return new CertificateIssuerIdentity {
                            RawIssuer = rawIssuer,
                            Organization = organization,
                            CommonName = commonName,
                            NormalizedName = rule.NormalizedName,
                            AuthorityFamily = rule.AuthorityFamily,
                            IsKnownAuthority = true
                        };
                    }
                }
            }

            var fallback = organization ?? commonName ?? rawIssuer;
            if (string.IsNullOrWhiteSpace(fallback)) {
                fallback = "Unknown";
            }

            return new CertificateIssuerIdentity {
                RawIssuer = rawIssuer,
                Organization = organization,
                CommonName = commonName,
                NormalizedName = fallback,
                AuthorityFamily = null,
                IsKnownAuthority = false
            };
        }

        private static string? ExtractDistinguishedNameField(string distinguishedName, string key) {
            if (string.IsNullOrWhiteSpace(distinguishedName) || string.IsNullOrWhiteSpace(key)) {
                return null;
            }

            foreach (var segment in SplitDistinguishedName(distinguishedName)) {
                if (string.IsNullOrWhiteSpace(segment)) {
                    continue;
                }

                var idx = segment.IndexOf('=');
                if (idx <= 0) {
                    continue;
                }

                var name = segment.Substring(0, idx).Trim();
                if (!name.Equals(key, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }

                var value = segment.Substring(idx + 1).Trim();
                value = UnescapeDistinguishedNameValue(value);
                if (!string.IsNullOrWhiteSpace(value)) {
                    return value;
                }
            }

            return null;
        }

        private static IEnumerable<string> SplitDistinguishedName(string distinguishedName) {
            var parts = new List<string>();
            var start = 0;
            var inQuotes = false;
            var escaped = false;
            for (var i = 0; i < distinguishedName.Length; i++) {
                var ch = distinguishedName[i];
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (ch == '\\') {
                    escaped = true;
                    continue;
                }
                if (ch == '"') {
                    inQuotes = !inQuotes;
                    continue;
                }
                if (ch == ',' && !inQuotes) {
                    parts.Add(distinguishedName.Substring(start, i - start));
                    start = i + 1;
                }
            }
            if (start < distinguishedName.Length) {
                parts.Add(distinguishedName.Substring(start));
            } else if (start == distinguishedName.Length && distinguishedName.Length > 0 && distinguishedName[distinguishedName.Length - 1] == ',') {
                parts.Add(string.Empty);
            }

            return parts;
        }

        private static string UnescapeDistinguishedNameValue(string value) {
            var normalized = (value ?? string.Empty).Trim();
            if (normalized.Length >= 2 && normalized[0] == '"' && normalized[normalized.Length - 1] == '"') {
                normalized = normalized.Substring(1, normalized.Length - 2);
            }

            normalized = normalized.Replace("\\,", ",");
            normalized = normalized.Replace("\\+", "+");
            normalized = normalized.Replace("\\=", "=");
            normalized = normalized.Replace("\\\"", "\"");
            normalized = normalized.Replace("\\\\", "\\");
            return normalized.Trim();
        }
    }
}
