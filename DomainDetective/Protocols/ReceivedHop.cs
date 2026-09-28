using System;
using System.Text.RegularExpressions;
using MimeKit.Utils;

namespace DomainDetective;

/// <summary>Represents a parsed <c>Received</c> header hop.</summary>
public partial class ReceivedHop {
    /// <summary>Host specified in the <c>from</c> clause.</summary>
    public string? FromHost { get; set; }
    /// <summary>IP address specified in the <c>from</c> clause.</summary>
    public string? FromIp { get; set; }
    /// <summary>Host specified in the <c>by</c> clause.</summary>
    public string? ByHost { get; set; }
    /// <summary>IP address specified in the <c>by</c> clause.</summary>
    public string? ByIp { get; set; }
    /// <summary>Protocol specified in the <c>with</c> clause.</summary>
    public string? With { get; set; }
    /// <summary>Identifier specified in the <c>id</c> clause.</summary>
    public string? Id { get; set; }
    /// <summary>Recipient specified in the <c>for</c> clause.</summary>
    public string? For { get; set; }
    /// <summary>Timestamp at the end of the header.</summary>
    public DateTimeOffset? Timestamp { get; set; }
    /// <summary>Delay since the previous hop.</summary>
    public TimeSpan? HopDelay { get; set; }
    /// <summary>Zero-based order in which the header appeared in the message.</summary>
    public int HeaderIndex { get; set; }
    /// <summary>Raw header value.</summary>
    public string Raw { get; set; } = string.Empty;

    private static readonly Regex FoldingWhitespace = new("\r?\n[ \t]+", RegexOptions.Compiled);
    private static readonly Regex LinearWhitespace = new("[ \t]+", RegexOptions.Compiled);

    /// <summary>Parses a <c>Received</c> header value into a <see cref="ReceivedHop"/>.</summary>
    /// <param name="raw">Raw header value.</param>
    /// <returns>Parsed <see cref="ReceivedHop"/>.</returns>
    public static ReceivedHop Parse(string raw) {
        var hop = new ReceivedHop { Raw = raw };
        var noFold = FoldingWhitespace.Replace(raw, " ");
        var normalized = LinearWhitespace.Replace(noFold, " ").Trim();

        var idx = -1;
        var depth = 0;
        var quoted = false;
        var escaped = false;
        for (var i = 0; i < normalized.Length; i++) {
            var ch = normalized[i];
            if (!escaped) {
                if (ch == '"' && depth == 0) { quoted = !quoted; }
                else if (!quoted && ch == '(') { depth++; }
                else if (!quoted && ch == ')') { depth = Math.Max(0, depth - 1); }
                else if (!quoted && depth == 0 && ch == ';') { idx = i; }
            }
            escaped = !escaped && ch == '\\';
        }
        var before = normalized;
        if (idx >= 0) {
            var datePart = normalized.Substring(idx + 1).Trim();
            before = normalized.Substring(0, idx).Trim();
            if (DateUtils.TryParse(datePart, out var dt)) {
                hop.Timestamp = dt;
            }
        }

        hop.ParseDetails(normalized, before);
        return hop;
    }

}

