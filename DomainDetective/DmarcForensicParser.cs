using MimeKit;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace DomainDetective;

/// <summary>Parser for zipped DMARC forensic reports.</summary>
public static class DmarcForensicParser {
    /// <summary>Parses the specified zip file.</summary>
    /// <param name="path">Path to the zipped report.</param>
    /// <returns>Enumerable of parsed reports.</returns>
    public static IEnumerable<DmarcForensicReport> ParseZip(string path) {
        using var archive = ZipFile.OpenRead(path);
        foreach (var entry in archive.Entries.Where(e => e.FullName.EndsWith(".eml", StringComparison.OrdinalIgnoreCase))) {
            DmarcForensicReport? report = null;
            try {
                using var stream = entry.Open();
                report = ParseMessage(MimeMessage.Load(stream));
            } catch {
                // Ignore parsing errors for individual entries
            }
            if (report != null) {
                yield return report;
            }
        }
    }

    /// <summary>Parses DMARC forensic report from message body.</summary>
    /// <param name="message">MIME message to parse.</param>
    /// <returns>Parsed report, or null if parsing failed.</returns>
    public static DmarcForensicReport? ParseMessage(MimeMessage message) {
        // Extract report body from rfc822-headers part
        var part = message.BodyParts.FirstOrDefault(p =>
            p.ContentType.MimeType.Equals("text/rfc822-headers", StringComparison.OrdinalIgnoreCase) ||
            p.ContentType.MimeType.Equals("message/feedback-report", StringComparison.OrdinalIgnoreCase));
        if (part == null) {
            return null;
        }

        using var memory = new MemoryStream();
        switch (part) {
            case MimePart mime:
                mime.Content.DecodeTo(memory);
                break;
            case MessagePart msg:
                msg.Message.WriteTo(memory);
                break;
            default:
                return null;
        }
        memory.Position = 0;

        var report = new DmarcForensicReport();
        using var reader = new StreamReader(memory);
        string? line;
        while ((line = reader.ReadLine()) != null) {
            if (line.StartsWith("Received-SPF:", StringComparison.OrdinalIgnoreCase)) {
                // Extract source IP from SPF header
                const string ipPrefix = "client-ip=";
                var start = line.IndexOf(ipPrefix, StringComparison.OrdinalIgnoreCase);
                if (start >= 0) {
                    start += ipPrefix.Length;
                    var end = line.IndexOf(';', start);
                    report.SourceIp = end >= 0 ? line.Substring(start, end - start).Trim() : line.Substring(start).Trim();
                }
            } else if (line.StartsWith("Source-IP:", StringComparison.OrdinalIgnoreCase)) {
                report.SourceIp = line.Substring(10).Trim();
            } else if (line.StartsWith("From:", StringComparison.OrdinalIgnoreCase)) {
                // Extract from domain
                var match = System.Text.RegularExpressions.Regex.Match(line, @"<([^>]+)>");
                report.HeaderFrom = match.Success ? match.Groups[1].Value : line.Substring(5).Trim();
            } else if (line.StartsWith("Reported-Domain:", StringComparison.OrdinalIgnoreCase)) {
                report.HeaderFrom = line.Substring(16).Trim();
            } else if (line.StartsWith("Original-Mail-From:", StringComparison.OrdinalIgnoreCase)) {
                report.OriginalMailFrom = line.Substring(19).Trim().Trim('<', '>');
            } else if (line.StartsWith("Original-Rcpt-To:", StringComparison.OrdinalIgnoreCase)) {
                report.OriginalRcptTo = line.Substring(17).Trim().Trim('<', '>');
            } else if (line.StartsWith("Arrival-Date:", StringComparison.OrdinalIgnoreCase)) {
                var value = line.Substring(13).Trim();
                var comma = value.IndexOf(',');
                if (comma >= 0 && comma + 1 < value.Length) {
                    value = value.Substring(comma + 1).Trim();
                }
                if (DateTimeOffset.TryParse(value, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var date)) {
                    report.ArrivalDate = date;
                }
            }
        }

        return report;
    }
}