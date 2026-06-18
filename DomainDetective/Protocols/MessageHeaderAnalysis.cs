using MimeKit;
using MimeKit.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainDetective {
    /// <summary>
    /// Represents the results from parsing message headers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public partial class MessageHeaderAnalysis : IHasAssessments {
        /// <summary>Raw headers supplied for parsing.</summary>
        public string? RawHeaders { get; private set; }
        /// <summary>All parsed headers keyed by header name.</summary>
        public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Duplicate header values keyed by header name.</summary>
        public Dictionary<string, List<string>> DuplicateHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>List of parsed <c>Received</c> header hops in order.</summary>
        public List<ReceivedHop> ReceivedHops { get; } = new();
        /// <summary>Total message transit time across all hops.</summary>
        public TimeSpan? TotalTransitTime { get; private set; }
        /// <summary>Maximum delay between consecutive hops.</summary>
        public TimeSpan? MaxHopDelay { get; private set; }
        /// <summary>Minimum delay between consecutive hops.</summary>
        public TimeSpan? MinHopDelay { get; private set; }
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
        /// <summary>Ignored DKIM-Signature headers with invalid signature values.</summary>
        public List<string> InvalidDkimSignatures { get; } = new();

        private bool _hasTrustedAuthenticationResults;
        private string? _trustedDkimResult;
        private string? _trustedSpfResult;
        private string? _trustedDmarcResult;

        /// <summary>Collection of detected issues.</summary>
        public List<MessageHeaderIssue> Issues { get; } = new();

        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>
        /// Parses <paramref name="rawHeaders"/> into strongly typed properties.
        /// </summary>
        /// <param name="rawHeaders">Unparsed header text.</param>
        /// <param name="logger">Logger used for diagnostics.</param>
        public void Parse(string rawHeaders, InternalLogger? logger = null) {
            Parse(rawHeaders, logger, emitRouteDiagnostics: true);
        }

        internal void Parse(string rawHeaders, InternalLogger? logger, bool emitRouteDiagnostics) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "HEADERS") : null;
            RawHeaders = rawHeaders;
            Headers.Clear();
            DuplicateHeaders.Clear();
            ReceivedHops.Clear();
            SpamHeaders.Clear();
            Issues.Clear();
            Assessments.Clear();
            TotalTransitTime = null;
            MaxHopDelay = null;
            MinHopDelay = null;
            From = null;
            To = null;
            Subject = null;
            Date = null;
            DkimResult = null;
            SpfResult = null;
            DmarcResult = null;
            ArcResult = null;
            _hasTrustedAuthenticationResults = false;
            _trustedDkimResult = null;
            _trustedSpfResult = null;
            _trustedDmarcResult = null;
            ResetRouteDiagnostics();
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
                    try {
                        message = MimeMessage.Load(asciiStream);
                    } catch (FormatException ex) {
                        logger?.WriteErrorCode(MessageHeaderCodes.MimeParseFailed, "MimeKit failed to parse headers: {0}", ex.Message);
                        ParseManually(rawHeaders, logger);
                        ComputeTransitTime();
                        AnalyzeRouteHeaders(logger);
                        DetermineIssues();
                        if (emitRouteDiagnostics) {
                            EmitRouteDiagnostics(logger);
                        }
                        return;
                    }
                }
                foreach (var header in message.Headers) {
                    AddHeaderValue(header.Field, header.Value);
                }
                ComputeTransitTime();
            } catch (Exception ex) {
                logger?.WriteErrorCode(MessageHeaderCodes.ParseFailed, "Failed to parse message headers: {0}", ex.Message);
            }

            if (string.Equals(DkimResult, "pass", StringComparison.OrdinalIgnoreCase)) {
                logger?.WriteInformationCode(MessageHeaderCodes.DkimPass, "DKIM authentication passed");
            }
            if (string.Equals(SpfResult, "pass", StringComparison.OrdinalIgnoreCase)) {
                logger?.WriteInformationCode(MessageHeaderCodes.SpfPass, "SPF authentication passed");
            }
            if (string.Equals(DmarcResult, "pass", StringComparison.OrdinalIgnoreCase)) {
                logger?.WriteInformationCode(MessageHeaderCodes.DmarcPass, "DMARC authentication passed");
            }
            if (string.Equals(ArcResult, "pass", StringComparison.OrdinalIgnoreCase)) {
                logger?.WriteInformationCode(MessageHeaderCodes.ArcPass, "ARC authentication passed");
            }

            AnalyzeRouteHeaders(logger);
            DetermineIssues();
            if (emitRouteDiagnostics) {
                EmitRouteDiagnostics(logger);
            }
        }

        private static readonly Regex FoldingWhitespace = new("\r?\n[ \t]+", RegexOptions.Compiled);
        private static readonly Regex LinearWhitespace = new("[ \t]+", RegexOptions.Compiled);

        private static string CanonicalizeValue(string value) {
            var noFold = FoldingWhitespace.Replace(value, " ");
            var collapsed = LinearWhitespace.Replace(noFold, " ");
            return collapsed.Trim();
        }

        private void AddHeaderValue(string field, string value) {
            var normalized = CanonicalizeValue(value);
            var lower = field.ToLowerInvariant();

            if (lower == "dkim-signature" && !HasValidSignature(normalized)) {
                InvalidDkimSignatures.Add(normalized);
                AddIssue(MessageHeaderIssue.InvalidDkim);
                return;
            }

            if (Headers.TryGetValue(field, out var existing)) {
                if (!DuplicateHeaders.TryGetValue(field, out var list)) {
                    list = new List<string> { existing };
                    DuplicateHeaders[field] = list;
                }
                list.Add(normalized);
            }
            Headers[field] = normalized;

            switch (lower) {
                case "received":
                    ReceivedHops.Add(ReceivedHop.Parse(value));
                    break;
                case "from":
                    From = value;
                    break;
                case "to":
                    To = value;
                    break;
                case "subject":
                    Subject = value;
                    break;
                case "date":
                    if (DateUtils.TryParse(value, out var parsed)) {
                        Date = parsed;
                    }
                    break;
                case "authentication-results":
                    ParseAuthenticationResults(value);
                    break;
            }

            if (lower.StartsWith("x-spam-")) {
                SpamHeaders[field] = value;
            }
        }

        private void ParseManually(string text, InternalLogger? logger) {
            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            string? currentField = null;
            var value = new StringBuilder();

            void Commit() {
                if (currentField != null) {
                    AddHeaderValue(currentField, value.ToString());
                }
            }

            foreach (var line in lines) {
                if (string.IsNullOrEmpty(line)) {
                    Commit();
                    currentField = null;
                    value.Clear();
                    continue;
                }

                if (char.IsWhiteSpace(line[0])) {
                    if (currentField != null) {
                        value.Append(' ').Append(line.TrimStart());
                    }
                    continue;
                }

                Commit();
                var idx = line.IndexOf(':');
                if (idx <= 0) {
                    logger?.WriteErrorCode(MessageHeaderCodes.MalformedLine, "Malformed header line: {0}", line);
                    currentField = null;
                    value.Clear();
                    continue;
                }

                currentField = line.Substring(0, idx).Trim();
                value.Clear();
                value.Append(line.Substring(idx + 1).Trim());
            }

            Commit();
        }

        private void ParseAuthenticationResults(string value) {
            string? dkim = null;
            string? spf = null;
            string? dmarc = null;
            string? arc = null;

            foreach (var part in value.Split(';')) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("dkim=", StringComparison.OrdinalIgnoreCase)) {
                    dkim = trimmed.Substring(5).Trim();
                } else if (trimmed.StartsWith("spf=", StringComparison.OrdinalIgnoreCase)) {
                    spf = trimmed.Substring(4).Trim();
                } else if (trimmed.StartsWith("dmarc=", StringComparison.OrdinalIgnoreCase)) {
                    dmarc = trimmed.Substring(6).Trim();
                } else if (trimmed.StartsWith("arc=", StringComparison.OrdinalIgnoreCase)) {
                    arc = trimmed.Substring(4).Trim();
                }
            }

            if (dkim != null) {
                DkimResult = dkim;
            }
            if (spf != null) {
                SpfResult = spf;
            }
            if (dmarc != null) {
                DmarcResult = dmarc;
            }
            if (arc != null) {
                ArcResult = arc;
            }

            if (!_hasTrustedAuthenticationResults && (dkim != null || spf != null || dmarc != null || arc != null)) {
                _hasTrustedAuthenticationResults = true;
                _trustedDkimResult = dkim;
                _trustedSpfResult = spf;
                _trustedDmarcResult = dmarc;
            }
        }

        private static bool HasValidSignature(string value) {
            foreach (var part in value.Split(';')) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("b=", StringComparison.OrdinalIgnoreCase)) {
                    var sig = trimmed.Substring(2).Trim();
                    return IsValidBase64(sig);
                }
            }
            return false;
        }

        private static bool IsValidBase64(string input) {
            input = input.Trim();
            if (input.Length == 0 || input.Length % 4 != 0) {
                return false;
            }
#if NET8_0_OR_GREATER
            Span<byte> buffer = stackalloc byte[input.Length];
            return Convert.TryFromBase64String(input, buffer, out _);
#else
            try {
                Convert.FromBase64String(input);
                return true;
            } catch (FormatException) {
                return false;
            }
#endif
        }

        private void ComputeTransitTime() {
            MaxHopDelay = null;
            MinHopDelay = null;
            TotalTransitTime = null;
            if (ReceivedHops.Count == 0) {
                return;
            }

            ReceivedHops.Sort((a, b) => {
                if (a.Timestamp.HasValue && b.Timestamp.HasValue) {
                    return a.Timestamp.Value.CompareTo(b.Timestamp.Value);
                }
                if (a.Timestamp.HasValue) {
                    return -1;
                }
                if (b.Timestamp.HasValue) {
                    return 1;
                }
                return 0;
            });

            DateTimeOffset? first = null;
            DateTimeOffset? prev = null;
            foreach (var hop in ReceivedHops) {
                hop.HopDelay = null;
                if (!hop.Timestamp.HasValue) {
                    continue;
                }
                if (!first.HasValue) {
                    first = hop.Timestamp;
                }
                if (prev.HasValue) {
                    var delay = hop.Timestamp.Value - prev.Value;
                    hop.HopDelay = delay;
                    if (!MaxHopDelay.HasValue || delay > MaxHopDelay.Value) {
                        MaxHopDelay = delay;
                    }
                    if (!MinHopDelay.HasValue || delay < MinHopDelay.Value) {
                        MinHopDelay = delay;
                    }
                }
                prev = hop.Timestamp;
            }

            if (first.HasValue && prev.HasValue && prev > first) {
                TotalTransitTime = prev.Value - first.Value;
            }
        }

        private void AddIssue(MessageHeaderIssue issue) {
            if (!Issues.Contains(issue)) {
                Issues.Add(issue);
            }
        }

        private void DetermineIssues() {
            var dkimResult = DkimResult;
            if (InvalidDkimSignatures.Count > 0 ||
                (!string.IsNullOrWhiteSpace(dkimResult) &&
                 !string.Equals(dkimResult, "pass", StringComparison.OrdinalIgnoreCase))) {
                AddIssue(MessageHeaderIssue.InvalidDkim);
            }

            var arcResult = ArcResult;
            if (string.IsNullOrWhiteSpace(arcResult) ||
                string.Equals(arcResult, "none", StringComparison.OrdinalIgnoreCase)) {
                AddIssue(MessageHeaderIssue.MissingArc);
            } else if (!string.Equals(arcResult, "pass", StringComparison.OrdinalIgnoreCase)) {
                AddIssue(MessageHeaderIssue.InvalidArc);
            }

            DetermineRouteIssues();
        }
    }
}
