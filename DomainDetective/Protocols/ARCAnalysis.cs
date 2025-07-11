using MimeKit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DomainDetective {
    /// <summary>
    ///     Validates ARC headers following RFC 8617.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class ARCAnalysis {
        internal static Func<byte[], Stream> CreateStream = b => new MemoryStream(b);
        /// <summary>Collected ARC-Seal header values.</summary>
        public List<string> ArcSealHeaders { get; } = new();
        /// <summary>Collected ARC-Authentication-Results header values.</summary>
        public List<string> ArcAuthenticationResultsHeaders { get; } = new();
        /// <summary>True when any ARC headers were found.</summary>
        public bool ArcHeadersFound { get; private set; }
        /// <summary>Indicates whether the ARC chain is sequential and complete.</summary>
        public bool ValidChain { get; private set; }

        /// <summary>Resets all analysis properties.</summary>
        public void Reset() {
            ArcSealHeaders.Clear();
            ArcAuthenticationResultsHeaders.Clear();
            ArcHeadersFound = false;
            ValidChain = false;
        }

        /// <summary>
        /// Parses ARC headers from <paramref name="rawHeaders"/> and validates the chain.
        /// </summary>
        /// <param name="rawHeaders">Raw message headers.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        public void Analyze(string rawHeaders, InternalLogger? logger = null) {
            Reset();
            if (string.IsNullOrWhiteSpace(rawHeaders)) {
                logger?.WriteVerbose("No headers supplied for ARC analysis.");
                return;
            }

            try {
                var utf8Bytes = Encoding.UTF8.GetBytes(rawHeaders + "\r\n");
                using (var utf8Stream = CreateStream(utf8Bytes)) {
                    MimeMessage message;
                    try {
                        message = MimeMessage.Load(utf8Stream);
                    } catch (FormatException) {
                        var asciiBytes = Encoding.ASCII.GetBytes(rawHeaders + "\r\n");
                        using (var asciiStream = CreateStream(asciiBytes)) {
                            message = MimeMessage.Load(asciiStream);
                        }
                    }

                    foreach (var header in message.Headers) {
                        if (header.Field.Equals("ARC-Seal", StringComparison.OrdinalIgnoreCase)) {
                            ArcSealHeaders.Add(header.Value);
                        } else if (header.Field.Equals("ARC-Authentication-Results", StringComparison.OrdinalIgnoreCase)) {
                            ArcAuthenticationResultsHeaders.Add(header.Value);
                        }
                    }
                }
            } catch (Exception ex) {
                logger?.WriteError("Failed to parse ARC headers: {0}", ex.Message);
                return;
            }

            ArcHeadersFound = ArcSealHeaders.Count > 0 ||
                              ArcAuthenticationResultsHeaders.Count > 0;

            var sealSequence = new List<int>();
            var aarSequence = new List<int>();

            foreach (var seal in ArcSealHeaders) {
                if (!HasSignature(seal)) {
                    ValidChain = false;
                    return;
                }

                var inst = ParseInstance(seal);
                if (inst == null) {
                    ValidChain = false;
                    return;
                }

                sealSequence.Add(inst.Value);
            }

            foreach (var aar in ArcAuthenticationResultsHeaders) {
                var inst = ParseInstance(aar);
                if (inst == null) {
                    ValidChain = false;
                    return;
                }

                aarSequence.Add(inst.Value);
            }

            if (sealSequence.Count == 0 ||
                aarSequence.Count == 0 ||
                sealSequence.Count != aarSequence.Count) {
                ValidChain = false;
                return;
            }

            var count = sealSequence.Count;
            bool ascending = sealSequence[0] == 1 && aarSequence[0] == 1;
            bool descending = sealSequence[0] == count && aarSequence[0] == count;

            if (!ascending && !descending) {
                ValidChain = false;
                return;
            }

            for (var index = 0; index < count; index++) {
                var expected = ascending ? index + 1 : count - index;
                if (sealSequence[index] != expected || aarSequence[index] != expected) {
                    ValidChain = false;
                    return;
                }
            }

            ValidChain = true;
        }

        private static int? ParseInstance(string value) {
            foreach (var part in value.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("i=", StringComparison.OrdinalIgnoreCase)) {
                    if (int.TryParse(trimmed.Substring(2), out var num)) {
                        return num;
                    }
                }
            }
            return null;
        }

        private static bool HasSignature(string value) {
            foreach (var part in value.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("b=", StringComparison.OrdinalIgnoreCase)) {
                    return trimmed.Length > 2;
                }
            }
            return false;
        }
    }
}
