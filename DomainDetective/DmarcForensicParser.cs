using DomainDetective.Helpers;
using MimeKit;
using MimeKit.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace DomainDetective;

/// <summary>Parses DMARC failure-report evidence using MimeKit for MIME and header syntax.</summary>
public static class DmarcForensicParser {
    /// <summary>Parses .eml entries in the specified zip file, skipping malformed individual messages.</summary>
    public static IEnumerable<DmarcForensicReport> ParseZip(string path) {
        using var archive = ZipFile.OpenRead(path);
        foreach (var entry in archive.Entries.Where(e => e.FullName.EndsWith(".eml", StringComparison.OrdinalIgnoreCase))) {
            DmarcForensicReport? report = null;
            try {
                using var stream = entry.Open();
                using var message = MimeMessage.Load(stream);
                report = ParseMessage(message);
            } catch {
                // Preserve the existing per-entry best-effort ingestion contract.
            }
            if (report != null) yield return report;
        }
    }

    /// <summary>Parses a feedback-report MIME body, with its attached original headers used only for missing legacy fields.</summary>
    /// <remarks>Reported results are evidence supplied by the sender; this method does not authenticate the report.</remarks>
    public static DmarcForensicReport? ParseMessage(MimeMessage message) {
        if (message == null) throw new ArgumentNullException(nameof(message));
        if (message.Body is not Multipart body || !body.ContentType.MimeType.Equals("multipart/report", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(body.ContentType.Parameters["report-type"], "feedback-report", StringComparison.OrdinalIgnoreCase)) return null;
        // Interpret only this report's direct parts. An attached original message can
        // contain arbitrary MIME content, including another report.
        var parts = body.OfType<MimePart>().ToArray();
        var feedbackPart = parts.FirstOrDefault(part => IsType(part, "message/feedback-report"));
        var originalPart = parts.FirstOrDefault(part => IsType(part, "text/rfc822-headers"));
        var original = originalPart?.Content != null ? ReadHeaders(originalPart)
            : body.OfType<MessagePart>().FirstOrDefault()?.Message?.Headers;
        if (feedbackPart?.Content == null && original == null) return null;
        var feedback = feedbackPart?.Content != null ? ReadHeaders(feedbackPart) : null;
        var report = new DmarcForensicReport { HasFeedbackReport = feedback != null };
        if (feedback != null) {
            foreach (var header in feedback) {
                if (!report.FeedbackFields.TryGetValue(header.Field, out var values)) {
                    report.FeedbackFields[header.Field] = values = new List<string>();
                }
                values.Add(RawValue(header));
            }
        }
        string? Field(string name) => report.FeedbackFields.TryGetValue(name, out var values) ? values.FirstOrDefault() : null;
        report.SourceIp = Field("Source-IP") ?? HeaderValue(original, "Source-IP") ?? SpfClientIp(HeaderValue(original, "Received-SPF")) ?? string.Empty;
        report.HeaderFrom = Field("Reported-Domain") ?? FromDomain(original ?? feedback);
        report.OriginalMailFrom = (Field("Original-Mail-From") ?? HeaderValue(original, "Original-Mail-From") ?? string.Empty).Trim('<', '>');
        report.OriginalRcptTo = (Field("Original-Rcpt-To") ?? HeaderValue(original, "Original-Rcpt-To"))?.Trim('<', '>');
        var date = Field("Arrival-Date") ?? HeaderValue(original, "Arrival-Date");
        if (date != null && DateUtils.TryParse(date, out var arrival)) report.ArrivalDate = arrival;
        report.FeedbackType = Field("Feedback-Type");
        report.AuthFailure = Field("Auth-Failure");
        report.DeliveryResult = Field("Delivery-Result");
        report.DkimDomain = Field("DKIM-Domain");
        report.DkimIdentity = Field("DKIM-Identity");
        report.DkimSelector = Field("DKIM-Selector");
        report.SpfDns = Field("SPF-DNS");
        var alignment = Field("Identity-Alignment");
        bool validAlignment = alignment != null && ParseIdentityAlignment(alignment, report.IdentityAlignment);
        if (string.Equals(report.AuthFailure, "dmarc", StringComparison.OrdinalIgnoreCase)) {
            if (alignment == null) report.ValidationMessages.Add("RFC 9991 requires Identity-Alignment for a DMARC failure report.");
            else if (!validAlignment || report.FeedbackFields["Identity-Alignment"].Count != 1) {
                report.ValidationMessages.Add("Identity-Alignment must contain dkim, spf, or none without duplicates or mixing none with mechanisms.");
            }
            if (report.IdentityAlignment.Contains("dkim") && (string.IsNullOrWhiteSpace(report.DkimDomain)
                || string.IsNullOrWhiteSpace(report.DkimIdentity) || string.IsNullOrWhiteSpace(report.DkimSelector)))
                report.ValidationMessages.Add("An aligned DKIM failure requires DKIM-Domain, DKIM-Identity, and DKIM-Selector.");
            if (report.IdentityAlignment.Contains("spf") && string.IsNullOrWhiteSpace(report.SpfDns))
                report.ValidationMessages.Add("An aligned SPF failure requires SPF-DNS.");
        }
        return report;
    }

    private static bool IsType(MimePart part, string type) => string.Equals(part.ContentType.MimeType, type, StringComparison.OrdinalIgnoreCase);
    private static HeaderList ReadHeaders(MimePart part) {
        using var memory = new MemoryStream();
        part.Content!.DecodeTo(memory);
        memory.Position = 0;
        return HeaderList.Load(memory);
    }
    private static string RawValue(Header header) => Header.Unfold(Encoding.UTF8.GetString(header.RawValue)).Trim();
    private static string? HeaderValue(HeaderList? headers, string name) {
        var header = headers?.FirstOrDefault(value => value.Field.Equals(name, StringComparison.OrdinalIgnoreCase));
        return header != null ? RawValue(header) : null;
    }
    private static string? FromDomain(HeaderList? headers) {
        var from = HeaderValue(headers, "From");
        if (from == null || !InternetAddressList.TryParse(from, out var addresses)) return null;
        var address = addresses.Mailboxes.FirstOrDefault()?.Address;
        int at = address?.LastIndexOf('@') ?? -1;
        if (at < 0) return null;
        try { return DomainHelper.ValidateIdn(address!.Substring(at + 1)); }
        catch (ArgumentException) { return null; }
    }
    private static string? SpfClientIp(string? value) {
        if (value == null) return null;
        int start = value.IndexOf("client-ip=", StringComparison.OrdinalIgnoreCase);
        if (start < 0) return null;
        start += "client-ip=".Length;
        int end = value.IndexOf(';', start);
        return (end < 0 ? value.Substring(start) : value.Substring(start, end - start)).Trim();
    }

    private static bool ParseIdentityAlignment(string value, List<string> mechanisms) {
        // This field's RFC 9991 grammar permits CFWS around comma-separated keywords.
        // MIME parsing/unfolding remains owned by MimeKit; comments here are field syntax.
        var text = new StringBuilder(value.Length);
        int depth = 0;
        for (int index = 0; index < value.Length; index++) {
            char character = value[index];
            if (depth > 0 && character == '\\') {
                if (++index == value.Length) return false;
            } else if (character == '(') {
                if (depth++ == 0) text.Append(' ');
            } else if (character == ')') {
                if (depth == 0) return false;
                depth--;
            } else if (depth == 0) text.Append(character);
        }
        if (depth != 0) return false;
        mechanisms.AddRange(text.ToString().Split(',').Select(token => token.Trim().ToLowerInvariant()));
        return mechanisms.Count > 0 && mechanisms.All(token => token == "dkim" || token == "spf" || token == "none")
            && mechanisms.Distinct(StringComparer.Ordinal).Count() == mechanisms.Count
            && (!mechanisms.Contains("none") || mechanisms.Count == 1);
    }
}
