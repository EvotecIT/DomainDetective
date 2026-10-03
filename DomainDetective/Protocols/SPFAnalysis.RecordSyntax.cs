using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace DomainDetective;

public partial class SpfAnalysis {
    private static readonly Regex SpfModifierName = new(@"^[A-Za-z][A-Za-z0-9_.-]*$", RegexOptions.Compiled);
    private static readonly Regex SpfMacroString = new(@"^(?:%\{[slodipvhcrt][0-9]*r?[.\-+,/_=]*\}|%%|%_|%-|[\x21-\x24\x26-\x7E])*$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex SpfCidr = new(@"^(?:0|[1-9][0-9]*)$", RegexOptions.Compiled);

    // RFC 7208 4.6.1 requires syntax checking of the entire policy before matching.
    private static bool TryValidateSpfSyntax(string record, out string[] tokens, out string? invalidToken, out string? invalidType) {
        tokens = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        invalidToken = null;
        invalidType = null;
        if (tokens.Length == 0 || !tokens[0].Equals("v=spf1", StringComparison.OrdinalIgnoreCase)
            || record.Length == 0 || record[0] == ' ' || record.Any(c => c < 32 || c > 126)) {
            return false;
        }
        var modifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string term in tokens.Skip(1)) {
            invalidToken = term;
            if (TryGetSpfModifier(term, out string name, out string value)) {
                invalidType = name;
                if (!modifiers.Add(name) || !SpfMacroString.IsMatch(value)) return false;
                if ((name.Equals("redirect", StringComparison.OrdinalIgnoreCase) || name.Equals("exp", StringComparison.OrdinalIgnoreCase))
                    && !ValidSpfDomainSpec(value)) return false;
                continue;
            }
            string mechanism = "+-~?".IndexOf(term[0]) >= 0 ? term.Substring(1) : term;
            int end = mechanism.IndexOfAny(new[] { ':', '/' });
            name = (end < 0 ? mechanism : mechanism.Substring(0, end)).ToLowerInvariant();
            invalidType = name;
            switch (name) {
                case "all":
                    if (!mechanism.Equals("all", StringComparison.OrdinalIgnoreCase)) return false;
                    break;
                case "ip4":
                case "ip6":
                    if (!mechanism.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)
                        || !ValidSpfAddress(mechanism.Substring(4), name == "ip4" ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6)) return false;
                    break;
                case "a":
                case "mx":
                    if (!ValidSpfAddressMechanism(mechanism, name)) return false;
                    break;
                case "include":
                case "exists":
                    if (!mechanism.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)
                        || !ValidSpfDomainSpec(mechanism.Substring(name.Length + 1))) return false;
                    break;
                case "ptr":
                    if (!mechanism.Equals("ptr", StringComparison.OrdinalIgnoreCase)
                        && (!mechanism.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase) || !ValidSpfDomainSpec(mechanism.Substring(4)))) return false;
                    break;
                default:
                    invalidType = "unknown";
                    return false;
            }
        }
        invalidToken = null;
        invalidType = null;
        return true;
    }

    private static bool TryGetSpfModifier(string token, out string name, out string value) {
        int equals = token.IndexOf('=');
        name = equals > 0 ? token.Substring(0, equals) : string.Empty;
        value = equals > 0 ? token.Substring(equals + 1) : string.Empty;
        return equals > 0 && SpfModifierName.IsMatch(name);
    }

    private static bool ValidSpfDomainSpec(string domain) {
        if (domain.Length == 0 || !SpfMacroString.IsMatch(domain)) return false;
        // c/r/t are permitted only in explanation text, never in a DNS target.
        if (Regex.IsMatch(domain, @"%\{[crt]", RegexOptions.IgnoreCase)) return false;
        if (domain.EndsWith("}", StringComparison.Ordinal) || domain.EndsWith("%%", StringComparison.Ordinal)
            || domain.EndsWith("%_", StringComparison.Ordinal) || domain.EndsWith("%-", StringComparison.Ordinal)) return true;
        string[] labels = domain.TrimEnd('.').Split('.');
        return labels.Length > 1 && Regex.IsMatch(labels[labels.Length - 1], @"^(?:[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*|[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9])$");
    }

    private static bool ValidSpfAddress(string cidr, AddressFamily family) {
        string[] parts = cidr.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address) || address.AddressFamily != family) return false;
        if (family == AddressFamily.InterNetwork && !Regex.IsMatch(parts[0], @"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$")) return false;
        if (family == AddressFamily.InterNetworkV6 && parts[0].IndexOf('%') >= 0) return false;
        return parts.Length == 1 || ValidSpfPrefix(parts[1], family == AddressFamily.InterNetwork ? 32 : 128);
    }

    private static bool ValidSpfPrefix(string text, int maximum) => SpfCidr.IsMatch(text)
        && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) && prefix <= maximum;

    private static bool ValidSpfAddressMechanism(string mechanism, string name) {
        string suffix = mechanism.Substring(name.Length);
        int slash = SpfCidrStart(suffix);
        string domain = slash < 0 ? suffix : suffix.Substring(0, slash);
        if (domain.Length > 0 && (!domain.StartsWith(":", StringComparison.Ordinal) || !ValidSpfDomainSpec(domain.Substring(1)))) return false;
        if (slash < 0) return true;
        string cidr = suffix.Substring(slash);
        int doubleSlash = cidr.IndexOf("//", StringComparison.Ordinal);
        if (doubleSlash >= 0) {
            if (!ValidSpfPrefix(cidr.Substring(doubleSlash + 2), 128)) return false;
            cidr = cidr.Substring(0, doubleSlash);
        }
        return cidr.Length == 0 || cidr.StartsWith("/", StringComparison.Ordinal) && ValidSpfPrefix(cidr.Substring(1), 32);
    }

    private static int SpfCidrStart(string suffix) {
        bool macro = false;
        for (int i = 0; i < suffix.Length; i++) {
            if (suffix[i] == '{') macro = true;
            else if (suffix[i] == '}') macro = false;
            else if (suffix[i] == '/' && !macro) return i;
        }
        return -1;
    }
}
