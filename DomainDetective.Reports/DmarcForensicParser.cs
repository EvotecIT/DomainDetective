using MimeKit;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>DMARC forensic report details.</summary>
public sealed class DmarcForensicReport {
    /// <summary>IP address of the sending host.</summary>
    public string SourceIp { get; set; } = string.Empty;
    /// <summary>Envelope from address.</summary>
    public string OriginalMailFrom { get; set; } = string.Empty;
    /// <summary>Original recipient address.</summary>
    public string? OriginalRcptTo { get; set; }
    /// <summary>Domain from the From header.</summary>
    public string? HeaderFrom { get; set; }
    /// <summary>Arrival date of the message.</summary>
    public DateTimeOffset? ArrivalDate { get; set; }
}

/// <summary>Parser for zipped DMARC forensic reports.</summary>
public static class DmarcForensicParser {
    /// <summary>Parses the specified zip file.</summary>
    /// <param name="path">Path to the zipped report.</param>
    /// <returns>Enumerable of parsed reports.</returns>
    public static IEnumerable<DmarcForensicReport> ParseZip(string path) {
        using var archive = ZipFile.OpenRead(path);
        foreach (var entry in archive.Entries.Where(e => e.Length > 0)) {
            using var stream = entry.Open();
            yield return Parse(stream);
        }
    }

    private static DmarcForensicReport Parse(Stream stream) {
        var message = MimeMessage.Load(stream);
        var reportPart = message.BodyParts.FirstOrDefault(p =>
            p.ContentType.MediaType.Equals("message", StringComparison.OrdinalIgnoreCase)
            && p.ContentType.MediaSubtype.Equals("feedback-report", StringComparison.OrdinalIgnoreCase));
        string text = string.Empty;
        if (reportPart is TextPart textPart) {
            text = textPart.Text;
        } else if (reportPart != null) {
            using var ms = new MemoryStream();
            reportPart.WriteTo(ms);
            ms.Position = 0;
            using var reader = new StreamReader(ms);
            text = reader.ReadToEnd();
        }
        var result = new DmarcForensicReport();
        foreach (var line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)) {
            var kv = line.Split(new[] { ':' }, 2);
            if (kv.Length != 2) {
                continue;
            }
            var key = kv[0].Trim();
            var value = kv[1].Trim();
            switch (key.ToLowerInvariant()) {
                case "source-ip":
                    result.SourceIp = value;
                    break;
                case "original-mail-from":
                    result.OriginalMailFrom = value;
                    break;
                case "original-rcpt-to":
                    result.OriginalRcptTo = value;
                    break;
                case "header-from":
                case "reported-domain":
                    result.HeaderFrom = value;
                    break;
                case "arrival-date":
                    if (MimeKit.Utils.DateUtils.TryParse(value, out var parsed)) {
                        result.ArrivalDate = parsed;
                    }
                    break;
            }
        }
        if (string.IsNullOrEmpty(result.HeaderFrom)) {
            var addr = message.From.Mailboxes.FirstOrDefault()?.Address;
            result.HeaderFrom = addr;
        }
        return result;
    }
}
