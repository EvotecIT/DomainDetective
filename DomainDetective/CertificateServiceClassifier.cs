using System;

namespace DomainDetective {
    /// <summary>
    /// Represents normalized endpoint details for certificate monitoring targets.
    /// </summary>
    public sealed class CertificateServiceDescriptor {
        /// <summary>Gets or sets the url value.</summary>
        public string Url { get; set; } = string.Empty;
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Gets or sets the scheme value.</summary>
        public string Scheme { get; set; } = "https";
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; }
        /// <summary>Gets or sets the service value.</summary>
        public string Service { get; set; } = "Custom TLS";
    }

    /// <summary>
    /// Resolves endpoint metadata (URL/scheme/port/service) for certificate checks.
    /// </summary>
    public static class CertificateServiceClassifier {
        /// <summary>Executes the resolve operation.</summary>
        public static CertificateServiceDescriptor Resolve(string hostOrUrl, int defaultPort) {
            if (string.IsNullOrWhiteSpace(hostOrUrl)) {
                throw new ArgumentNullException(nameof(hostOrUrl));
            }

            var raw = hostOrUrl.Trim();
            var candidate = raw;
            if (candidate.IndexOf("://", StringComparison.Ordinal) < 0) {
                candidate = $"https://{candidate}";
            }

            if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri)) {
                throw new ArgumentException($"Invalid host or URL '{hostOrUrl}'.", nameof(hostOrUrl));
            }

            var resolvedPort = uri.IsDefaultPort ? defaultPort : uri.Port;
            var builder = new UriBuilder(uri) {
                Scheme = Uri.UriSchemeHttps,
                Port = resolvedPort
            };

            var scheme = builder.Scheme.ToLowerInvariant();
            var service = GuessService(scheme, resolvedPort);
            return new CertificateServiceDescriptor {
                Url = builder.Uri.ToString(),
                Host = builder.Host,
                Scheme = scheme,
                Port = resolvedPort,
                Service = service
            };
        }

        /// <summary>Executes the guess service operation.</summary>
        public static string GuessService(string scheme, int port) {
            if (scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) {
                if (port == 443) {
                    return "HTTPS";
                }
                if (port == 8443 || port == 9443 || port == 4443) {
                    return "HTTPS-Alt";
                }
            }

            return port switch {
                443 => "HTTPS",
                8443 => "HTTPS-Alt",
                9443 => "HTTPS-Alt",
                4443 => "HTTPS-Alt",
                990 => "FTPS",
                636 => "LDAPS",
                3389 => "RDP-TLS",
                _ => "Custom TLS"
            };
        }
    }
}
