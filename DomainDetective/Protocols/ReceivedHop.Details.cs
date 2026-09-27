using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainDetective;

public partial class ReceivedHop {
    /// <summary>Reported TLS version. Header text does not independently prove encryption.</summary>
    public string? TlsVersion { get; private set; }
    /// <summary>Reported TLS cipher, if available.</summary>
    public string? TlsCipher { get; private set; }
    /// <summary>Protocol class inferred from RFC 3848 tokens and reported TLS details.</summary>
    public string? ProtocolClass { get; private set; }
    /// <summary>Reported HELO identity, if available.</summary>
    public string? Helo { get; private set; }
    /// <summary>Reverse DNS name reported in a comment; no live lookup is performed.</summary>
    public string? ReportedReverseDns { get; private set; }
    /// <summary>Whether the reported source IP is private, local, or shared address space.</summary>
    public bool IsPrivateIp { get; private set; }
    /// <summary>Transport detail supplied in the via clause.</summary>
    public string? Via { get; private set; }
    /// <summary>Provider name hints from reported route hosts. These do not establish provider ownership or trust.</summary>
    public IReadOnlyList<string> ProviderHints { get; private set; } = Array.Empty<string>();

    private static readonly Regex ClausePattern = new(@"\b(?<key>from|by|with|via|id|for)\s+", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex AddressPattern = new(@"\[(?:IPv6:)?(?<ip>[0-9a-f:.%]+)\]|\b(?<ip>(?:\d{1,3}\.){3}\d{1,3})\b", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex TlsPattern = new(@"\b(?:version\s*=\s*|using\s+)?(?<version>TLSv?[_ .]?1[_.]?[0-3])\b(?!\.[a-z0-9_-])", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex CipherPattern = new(@"\bcipher\s*[= ]\s*(?<cipher>[a-z0-9_-]+)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex EximCipherPattern = new(@"\bX=TLSv?1[._][0-3]:(?<cipher>[a-z0-9_-]+)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex HeloPattern = new(@"\bhelo\s*=\s*(?<host>[^\s)]+)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex ReversePattern = new(@"\(\s*(?<host>[a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\.?\s+\[", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));

    private void ParseDetails(string normalized, string beforeDate) {
        var matches = ClausePattern.Matches(SearchableReceivedText(beforeDate, hideComments: true));
        var identityText = SearchableReceivedText(normalized, hideComments: false);
        var clauses = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < matches.Count; i++) {
            var match = matches[i];
            var end = i + 1 < matches.Count ? matches[i + 1].Index : beforeDate.Length;
            clauses[match.Groups["key"].Value] = beforeDate.Substring(match.Index + match.Length, end - match.Index - match.Length).Trim();
        }
        string? Host(string key) {
            if (!clauses.TryGetValue(key, out var value)) { return null; }
            var parts = value.Split(new[] { ' ', '\t', '(' }, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length == 0 || value.StartsWith("(", StringComparison.Ordinal) ? null : parts[0].TrimEnd('.');
        }
        FromHost = Host("from");
        ByHost = Host("by");
        ProviderHints = Providers.Email.EmailProviderDetector.DetectReportedHost(ByHost ?? FromHost);
        With = Host("with");
        Id = Host("id");
        For = clauses.TryGetValue("for", out var recipient) ? recipient : null;
        Via = Host("via");
        FromIp = clauses.TryGetValue("from", out var source) ? ParseIp(source) : null;
        ByIp = clauses.TryGetValue("by", out var destination) ? ParseIp(destination) : null;
        // TLS markers may be reported in transport clauses or connection comments.
        // Hostnames, message IDs and recipients are identities, not TLS evidence.
        string TransportClause(string key, bool omitHost) {
            if (!clauses.TryGetValue(key, out var value)) { return string.Empty; }
            if (!omitHost || value.StartsWith("(", StringComparison.Ordinal)) { return value; }
            var separator = value.IndexOfAny(new[] { ' ', '\t', '(' });
            return separator < 0 ? string.Empty : value.Substring(separator).Trim();
        }
        var transportText = SearchableReceivedText(string.Join(" ", new[] {
            TransportClause("from", true), TransportClause("by", true),
            TransportClause("with", false), TransportClause("via", true)
        }), hideComments: false);
        transportText = HeloPattern.Replace(transportText, " ");
        var helo = HeloPattern.Match(identityText);
        Helo = helo.Success ? helo.Groups["host"].Value : FromHost;
        var reverse = ReversePattern.Match(source ?? string.Empty);
        ReportedReverseDns = reverse.Success ? reverse.Groups["host"].Value : null;
        var tls = TlsPattern.Match(transportText);
        TlsVersion = tls.Success ? "TLS " + tls.Groups["version"].Value.ToUpperInvariant().Replace("TLS", "").Replace("V", "").Replace("_", ".").Replace(" ", "").TrimStart('.') : null;
        var cipher = CipherPattern.Match(transportText);
        if (!cipher.Success) { cipher = EximCipherPattern.Match(transportText); }
        TlsCipher = cipher.Success ? cipher.Groups["cipher"].Value : null;
        var protocol = (With ?? string.Empty).ToUpperInvariant();
        ProtocolClass = protocol.Contains("HTTP") ? "Http" : protocol.Contains("MAPI") ? "Mapi"
            : protocol.Contains("LOCAL") ? "Local" : protocol.EndsWith("SMTPSA", StringComparison.Ordinal) || protocol.EndsWith("LMTPSA", StringComparison.Ordinal) ? "TlsAuthenticated"
            : protocol.EndsWith("SMTPA", StringComparison.Ordinal) || protocol.EndsWith("LMTPA", StringComparison.Ordinal) ? (TlsVersion != null ? "TlsAuthenticated" : "Authenticated")
            : protocol.EndsWith("SMTPS", StringComparison.Ordinal) || protocol.EndsWith("LMTPS", StringComparison.Ordinal) || TlsVersion != null ? "Tls"
            : protocol.Contains("SMTP") || protocol.Contains("LMTP") ? "Plain" : null;
        if (IPAddress.TryParse(FromIp, out var ip)) {
            if (ip.IsIPv4MappedToIPv6) { ip = ip.MapToIPv4(); }
            var bytes = ip.GetAddressBytes();
            IsPrivateIp = IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal
                || (bytes.Length == 16 && (bytes[0] & 0xfe) == 0xfc)
                || (bytes.Length == 4 && (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168) || (bytes[0] == 169 && bytes[1] == 254) || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)));
        }
    }

    private static string SearchableReceivedText(string value, bool hideComments) {
        var mask = new StringBuilder(value.Length);
        var depth = 0;
        var quoted = false;
        var escaped = false;
        foreach (var ch in value) {
            var wasComment = depth > 0;
            if (!escaped) {
                if (ch == '"' && depth == 0) { quoted = !quoted; }
                else if (!quoted && ch == '(') { depth++; }
                else if (!quoted && ch == ')') { depth = Math.Max(0, depth - 1); }
            }
            mask.Append(quoted || (ch == '"' && !wasComment) || (hideComments && (depth > 0 || wasComment)) ? ' ' : ch);
            escaped = !escaped && ch == '\\';
        }
        return mask.ToString();
    }

    private static string? ParseIp(string text) {
        foreach (Match match in AddressPattern.Matches(text)) {
            if (IPAddress.TryParse(match.Groups["ip"].Value, out var ip)) { return ip.ToString(); }
        }
        return null;
    }
}
