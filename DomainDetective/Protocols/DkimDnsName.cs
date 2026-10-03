using System;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>DNS names for DKIM and ARC, including RFC 8616 A-label conversion.</summary>
internal static class DkimDnsName {
    internal static string Selector(string selector) {
        if (string.IsNullOrWhiteSpace(selector)) throw new ArgumentException("Invalid DKIM selector.", nameof(selector));
        string ascii = new IdnMapping().GetAscii(selector);
        if (ascii.Length > 253 || !Regex.IsMatch(ascii, @"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$", RegexOptions.IgnoreCase)
            || ascii.Split('.').Any(label => label.Length > 63)) throw new ArgumentException("Invalid DKIM selector.", nameof(selector));
        return ascii.ToLowerInvariant();
    }

    internal static string Lookup(string domain, string selector) {
        string host = Selector(selector) + "._domainkey." + Helpers.DomainHelper.ValidateIdn(domain).ToLowerInvariant();
        if (host.Length > 253) throw new ArgumentException("DKIM key lookup name exceeds DNS limits.", nameof(selector));
        return host;
    }

    internal static string NormalizeRecordName(string name) => new IdnMapping().GetAscii(name.Trim().TrimEnd('.')).ToLowerInvariant();
}
