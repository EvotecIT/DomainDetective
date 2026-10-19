using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DomainDetective;

public sealed partial class CtLogAggregator {
    // These expressions read the provider's fixed certificate-summary table, not arbitrary HTML.
    // Missing or changed structure stays unknown; only a matching fingerprint can establish evidence.
    private static readonly TimeSpan CrtShParseBudget = TimeSpan.FromMilliseconds(250);
    private const RegexOptions CrtShOptions = RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant;

    private static MatchCollection CrtShMatches(string text, string expression) =>
        Regex.Matches(text, expression, CrtShOptions, CrtShParseBudget);

    private static string CrtShText(string html) => Regex.Replace(
        WebUtility.HtmlDecode(Regex.Replace(html, "<[^>]*>", " ", CrtShOptions, CrtShParseBudget)),
        @"\s+", " ", CrtShOptions, CrtShParseBudget).Trim();

    /// <summary>Reads crt.sh's fingerprint-specific CT table and retains verified rows when another row is malformed.</summary>
    private static FetchResult ParseCrtShCertificatePage(string html, string fingerprint) {
        var entries = new List<JsonElement>();
        if (html.Length > 4 * 1024 * 1024 || !Regex.IsMatch(fingerprint, @"\A[0-9a-f]{64}\z", CrtShOptions, CrtShParseBudget)) {
            return new FetchResult(false, entries);
        }
        try {
            var criteria = CrtShMatches(html, @"<TH\b[^>]*>\s*Criteria\s*</TH>\s*<TD\b[^>]*>(.*?)</TD>");
            if (criteria.Count != 1 || !string.Equals(CrtShText(criteria[0].Groups[1].Value),
                $"SHA-256(Certificate) = '{fingerprint}'", StringComparison.OrdinalIgnoreCase)) {
                return new FetchResult(false, entries);
            }
            var tables = CrtShMatches(html, @"<TH\b[^>]*>\s*Certificate\s+Transparency\s*</TH>\s*<TD\b[^>]*>\s*<DIV\b[^>]*>\s*<TABLE\b[^>]*>(.*?)</TABLE>");
            if (tables.Count != 1) { return new FetchResult(false, entries); }
            var rows = CrtShMatches(tables[0].Groups[1].Value, @"<TR\b[^>]*>(.*?)</TR>");
            if (rows.Count < 2) { return new FetchResult(false, entries); }
            var headings = CrtShMatches(rows[0].Groups[1].Value, @"<TH\b[^>]*>(.*?)</TH>");
            var expected = new[] { "Timestamp", "Entry #", "Log Operator", "Log URL" };
            if (headings.Count != expected.Length) { return new FetchResult(false, entries); }
            for (int index = 0; index < expected.Length; index++) {
                if (CrtShText(headings[index].Groups[1].Value) != expected[index]) { return new FetchResult(false, entries); }
            }
            bool complete = Regex.Replace(tables[0].Groups[1].Value, @"<TR\b[^>]*>.*?</TR>", "", CrtShOptions, CrtShParseBudget).Trim().Length == 0;
            for (int index = 1; index < rows.Count; index++) {
                var cells = CrtShMatches(rows[index].Groups[1].Value, @"<TD\b[^>]*>(.*?)</TD>");
                if (cells.Count == 1 && rows.Count == 2 && CrtShText(cells[0].Groups[1].Value) == "No entries found") {
                    return new FetchResult(complete, entries);
                }
                if (cells.Count != 4 ||
                    !DateTimeOffset.TryParseExact(CrtShText(cells[0].Groups[1].Value), "yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var timestamp) ||
                    !long.TryParse(CrtShText(cells[1].Groups[1].Value), NumberStyles.None, CultureInfo.InvariantCulture, out var entryId) || entryId < 0 ||
                    !Uri.TryCreate(CrtShText(cells[3].Groups[1].Value), UriKind.Absolute, out var logUrl) ||
                    logUrl.Scheme != Uri.UriSchemeHttps && logUrl.Scheme != Uri.UriSchemeHttp) {
                    complete = false;
                    continue;
                }
                var serialized = JsonSerializer.Serialize(new {
                    sha256 = fingerprint.ToLowerInvariant(),
                    entry_timestamp = timestamp.ToString("O", CultureInfo.InvariantCulture),
                    entry_id = entryId,
                    log_operator = CrtShText(cells[2].Groups[1].Value),
                    log_url = logUrl.AbsoluteUri
                });
                using var document = JsonDocument.Parse(serialized);
                entries.Add(document.RootElement.Clone());
            }
            return new FetchResult(complete, entries);
        } catch (RegexMatchTimeoutException) {
            return new FetchResult(false, entries);
        }
    }
}
