using System;
using System.Text.RegularExpressions;
using MimeKit.Utils;

namespace DomainDetective;

/// <summary>Represents a parsed <c>Received</c> header hop.</summary>
public class ReceivedHop {
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
    /// <summary>Raw header value.</summary>
    public string Raw { get; set; } = string.Empty;

    private static readonly Regex FoldingWhitespace = new("\r?\n[ \t]+", RegexOptions.Compiled);
    private static readonly Regex LinearWhitespace = new("[ \t]+", RegexOptions.Compiled);
    private static readonly Regex HeaderRegex = new(
        @"^from\s+(?<fromHost>[^\s]+)(?:\s+\((?<fromDetails>.*?)\))?\s+by\s+(?<byHost>[^\s]+)(?:\s+\((?<byDetails>.*?)\))?(?:\s+with\s+(?<with>[^\s]+))?(?:\s+id\s+(?<id>[^\s]+))?(?:\s+for\s+(?<for>.+))?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Parses a <c>Received</c> header value into a <see cref="ReceivedHop"/>.</summary>
    /// <param name="raw">Raw header value.</param>
    /// <returns>Parsed <see cref="ReceivedHop"/>.</returns>
    public static ReceivedHop Parse(string raw) {
        var hop = new ReceivedHop { Raw = raw };
        var noFold = FoldingWhitespace.Replace(raw, " ");
        var normalized = LinearWhitespace.Replace(noFold, " ").Trim();

        var idx = normalized.LastIndexOf(';');
        var before = normalized;
        if (idx >= 0) {
            var datePart = normalized.Substring(idx + 1).Trim();
            before = normalized.Substring(0, idx).Trim();
            if (DateUtils.TryParse(datePart, out var dt)) {
                hop.Timestamp = dt;
            }
        }

        var match = HeaderRegex.Match(before);
        if (match.Success) {
            hop.FromHost = match.Groups["fromHost"].Value;
            hop.ByHost = match.Groups["byHost"].Value;
            if (match.Groups["with"].Success) {
                hop.With = match.Groups["with"].Value;
            }
            if (match.Groups["id"].Success) {
                hop.Id = match.Groups["id"].Value;
            }
            if (match.Groups["for"].Success) {
                hop.For = match.Groups["for"].Value;
            }

            var fromDetails = match.Groups["fromDetails"].Value;
            if (!string.IsNullOrEmpty(fromDetails)) {
                var ipMatch = Regex.Match(fromDetails, @"\[(?<ip>[0-9A-Fa-f:.]+)\]");
                if (ipMatch.Success) {
                    hop.FromIp = ipMatch.Groups["ip"].Value;
                }
            }
            var byDetails = match.Groups["byDetails"].Value;
            if (!string.IsNullOrEmpty(byDetails)) {
                var ipMatch = Regex.Match(byDetails, @"\[(?<ip>[0-9A-Fa-f:.]+)\]");
                if (ipMatch.Success) {
                    hop.ByIp = ipMatch.Groups["ip"].Value;
                }
            }
        }

        return hop;
    }
}

