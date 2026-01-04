using System;
using System.Globalization;
using System.Text.RegularExpressions;

namespace DomainDetective.Helpers;

public static class DomainHelper {
    private static readonly IdnMapping _idn = new();
    private static readonly Regex _tldRegex = new(
        "^[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
        RegexOptions.Compiled);

    public static string ValidateIdn(string domain) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        try {
            var ascii = _idn.GetAscii(domain.Trim().Trim('.'));
            if (Uri.CheckHostName(ascii) != UriHostNameType.Dns) {
                throw new ArgumentException("Invalid domain name.", nameof(domain));
            }
            return ascii;
        } catch (ArgumentException e) {
            throw new ArgumentException("Invalid domain name.", nameof(domain), e);
        }
    }

    public static bool IsValidTld(string tld) =>
        _tldRegex.IsMatch(tld ?? string.Empty);

    public static bool IsDomainOrSubdomainOf(string? host, string? domain) {
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(domain)) {
            return false;
        }

        var normalizedHost = (host ?? string.Empty).Trim().TrimEnd('.');
        var normalizedDomain = (domain ?? string.Empty).Trim().Trim('.');

        if (normalizedHost.Length == 0 || normalizedDomain.Length == 0) {
            return false;
        }

        if (string.Equals(normalizedHost, normalizedDomain, StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        if (normalizedHost.Length <= normalizedDomain.Length) {
            return false;
        }

        if (!normalizedHost.EndsWith(normalizedDomain, StringComparison.OrdinalIgnoreCase)) {
            return false;
        }

        return normalizedHost[normalizedHost.Length - normalizedDomain.Length - 1] == '.';
    }
}
