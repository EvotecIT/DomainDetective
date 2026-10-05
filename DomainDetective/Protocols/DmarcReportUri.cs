using System;
using System.Linq;
using System.Net.Mail;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>Shared syntax checks for policy discovery and report destination analysis.</summary>
internal static class DmarcReportUri {
    internal static bool IsValid(string target) {
        string value = target.Trim();
        int limit = value.LastIndexOf('!');
        if (limit >= 0 && ParseSize(value.Substring(limit + 1)).HasValue) value = value.Substring(0, limit);
        if (value.IndexOf('!') >= 0 || value.Any(c => c <= ' ') || !Uri.TryCreate(value, UriKind.Absolute, out var uri)) return false;
        return uri.Scheme != "mailto" || TryReadMailbox(value.Substring(7), out _);
    }

    internal static bool TryReadMailbox(string address, out string mailbox) {
        mailbox = string.Empty;
        try {
            string decoded = Uri.UnescapeDataString(address);
            var parsed = new MailAddress(decoded);
            if (!string.Equals(parsed.Address, decoded, StringComparison.Ordinal)) return false;
            mailbox = parsed.Address;
            return true;
        } catch (ArgumentException) {
            return false;
        } catch (FormatException) {
            return false;
        }
    }

    internal static long? ParseSize(string value) {
        var match = Regex.Match(value, "^([0-9]+)([kKmMgGtT])?$");
        if (!match.Success || !long.TryParse(match.Groups[1].Value, out long size)) return null;
        long multiplier = match.Groups[2].Value.ToLowerInvariant() switch {
            "k" => 1024L,
            "m" => 1024L * 1024L,
            "g" => 1024L * 1024L * 1024L,
            "t" => 1024L * 1024L * 1024L * 1024L,
            _ => 1L
        };
        return size <= long.MaxValue / multiplier ? size * multiplier : null;
    }
}
