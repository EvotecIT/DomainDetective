using MimeKit;
using MimeKit.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DomainDetective {
    /// <summary>
    /// Represents the results from parsing message headers.
    /// </summary>
    public class MessageHeaderAnalysis {
        /// <summary>Raw headers supplied for parsing.</summary>
        public string? RawHeaders { get; private set; }
        /// <summary>All parsed headers keyed by header name.</summary>
        public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>List of <c>Received</c> header values in order.</summary>
        public List<string> ReceivedChain { get; } = new();
        /// <summary>Total message transit time across all hops.</summary>
        public TimeSpan? TotalTransitTime { get; private set; }
        /// <summary>Value of the <c>From</c> header.</summary>
        public string? From { get; private set; }
        /// <summary>Value of the <c>To</c> header.</summary>
        public string? To { get; private set; }
        /// <summary>Value of the <c>Subject</c> header.</summary>
        public string? Subject { get; private set; }
        /// <summary>Date of the message if present.</summary>
        public DateTimeOffset? Date { get; private set; }
        /// <summary>DKIM authentication result.</summary>
        public string? DkimResult { get; private set; }
        /// <summary>SPF authentication result.</summary>
        public string? SpfResult { get; private set; }
        /// <summary>DMARC authentication result.</summary>
        public string? DmarcResult { get; private set; }
        /// <summary>ARC authentication result.</summary>
        public string? ArcResult { get; private set; }
        /// <summary>Optional spam related headers.</summary>
        public Dictionary<string, string> SpamHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Parses <paramref name="rawHeaders"/> into strongly typed properties.
        /// </summary>
        /// <param name="rawHeaders">Unparsed header text.</param>
        /// <param name="logger">Logger used for diagnostics.</param>
        public void Parse(string rawHeaders, InternalLogger? logger = null) {
            RawHeaders = rawHeaders;
            Headers.Clear();
            ReceivedChain.Clear();
            SpamHeaders.Clear();
            TotalTransitTime = null;
            From = null;
            To = null;
            Subject = null;
            Date = null;
            DkimResult = null;
            SpfResult = null;
            DmarcResult = null;
            ArcResult = null;
            if (string.IsNullOrWhiteSpace(rawHeaders)) {
                logger?.WriteVerbose("No headers supplied for parsing.");
                return;
            }

            try {
                var utf8Bytes = Encoding.UTF8.GetBytes(rawHeaders + "\r\n");
                using var utf8Stream = new MemoryStream(utf8Bytes);
                MimeMessage message;
                try {
                    message = MimeMessage.Load(utf8Stream);
                } catch (FormatException) {
                    utf8Stream.Dispose();
                    var asciiBytes = Encoding.ASCII.GetBytes(rawHeaders + "\r\n");
                    using var asciiStream = new MemoryStream(asciiBytes);
                    message = MimeMessage.Load(asciiStream);
                }
                foreach (var header in message.Headers) {
                    Headers[header.Field] = header.Value;
                    switch (header.Id) {
                        case HeaderId.Received:
                            ReceivedChain.Add(header.Value);
                            break;
                        case HeaderId.From:
                            From = header.Value;
                            break;
                        case HeaderId.To:
                            To = header.Value;
                            break;
                        case HeaderId.Subject:
                            Subject = header.Value;
                            break;
                        case HeaderId.Date:
                            if (DateUtils.TryParse(header.Value, out var parsed)) {
                                Date = parsed;
                            }
                            break;
                        case HeaderId.AuthenticationResults:
                            ParseAuthenticationResults(header.Value);
                            break;
                    }
                    if (header.Field.StartsWith("X-Spam-", StringComparison.OrdinalIgnoreCase)) {
                        SpamHeaders[header.Field] = header.Value;
                    }
                }
                ComputeTransitTime();
            } catch (Exception ex) {
                logger?.WriteError("Failed to parse message headers: {0}", ex.Message);
            }
        }

        private void ParseAuthenticationResults(string value) {
            foreach (var part in value.Split(';')) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("dkim=", StringComparison.OrdinalIgnoreCase)) {
                    DkimResult = trimmed.Substring(5).Trim();
                } else if (trimmed.StartsWith("spf=", StringComparison.OrdinalIgnoreCase)) {
                    SpfResult = trimmed.Substring(4).Trim();
                } else if (trimmed.StartsWith("dmarc=", StringComparison.OrdinalIgnoreCase)) {
                    DmarcResult = trimmed.Substring(6).Trim();
                } else if (trimmed.StartsWith("arc=", StringComparison.OrdinalIgnoreCase)) {
                    ArcResult = trimmed.Substring(4).Trim();
                }
            }
        }

        private void ComputeTransitTime() {
            var times = new List<DateTimeOffset>();
            foreach (var received in ReceivedChain) {
                var idx = received.LastIndexOf(';');
                if (idx < 0) {
                    continue;
                }
                var datePart = received.Substring(idx + 1).Trim();
                if (DateUtils.TryParse(datePart, out var dt)) {
                    times.Add(dt);
                }
            }
            if (times.Count >= 2) {
                times.Sort();
                TotalTransitTime = times[times.Count-1] - times[0];
            }
        }
    }
}
