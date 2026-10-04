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
    /// <remarks>
    /// ARC (Authenticated Received Chain) is used to preserve authentication
    /// results during message forwarding. This analysis checks the chain for
    /// completeness and signature presence. It does not cryptographically verify signatures.
    /// </remarks>
    public class ARCAnalysis : IHasAssessments {
        internal static Func<byte[], Stream> CreateStream = b => new MemoryStream(b);
        /// <summary>Collected ARC-Seal header values.</summary>
        public List<string> ArcSealHeaders { get; } = new();
        /// <summary>Collected ARC-Authentication-Results header values.</summary>
        public List<string> ArcAuthenticationResultsHeaders { get; } = new();
        /// <summary>Collected ARC-Message-Signature values; required once per instance.</summary>
        public List<string> ArcMessageSignatureHeaders { get; } = new();
        /// <summary>Reasons the ARC header structure is incomplete or inconsistent.</summary>
        public List<string> StructureIssues { get; } = new();
        /// <summary>Reported ARC instances in ascending order, retaining their authentication claims.</summary>
        public List<MessageArcInstance> Instances { get; } = new();
        /// <summary>Whether an ARC seal declares a failed prior chain.</summary>
        public bool ChainValidationFailed { get; private set; }
        /// <summary>True when any ARC headers were found.</summary>
        public bool ArcHeadersFound { get; private set; }
        /// <summary>Whether ARC sets are complete and sequential with no declared failed chain; signatures are not cryptographically verified.</summary>
        public bool ValidChain { get; private set; }
        /// <summary>True when all ARC-Seal headers include signatures.</summary>
        public bool SealsIncludeSignatures { get; private set; }
        /// <summary>Structural and declared ARC chain status; signatures are not cryptographically verified.</summary>
        public ArcChainState ChainState { get; private set; } = ArcChainState.Missing;

        /// <summary>Resets all analysis properties.</summary>
        public void Reset() {
            ArcSealHeaders.Clear();
            ArcAuthenticationResultsHeaders.Clear();
            ArcMessageSignatureHeaders.Clear();
            StructureIssues.Clear();
            Instances.Clear();
            Assessments.Clear();
            ChainValidationFailed = false;
            ArcHeadersFound = false;
            ValidChain = false;
            SealsIncludeSignatures = false;
            ChainState = ArcChainState.Missing;
        }

        /// <summary>
        /// Parses ARC headers from <paramref name="rawHeaders"/> and validates the chain.
        /// </summary>
        /// <param name="rawHeaders">Raw message headers.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        public void Analyze(string rawHeaders, InternalLogger? logger = null) => Analyze(rawHeaders, 2 * 1024 * 1024, logger);

        /// <summary>Checks ARC structure with an explicit header character limit.</summary>
        /// <param name="rawHeaders">Raw message headers; body content is ignored.</param>
        /// <param name="maximumHeaderCharacters">Positive bound on the header block.</param>
        /// <param name="logger">Optional diagnostic logger.</param>
        public void Analyze(string rawHeaders, int maximumHeaderCharacters, InternalLogger? logger = null) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "ARC") : null;
            Reset();
            rawHeaders = MessageHeaderAnalysis.ExtractMessageHeaderBlock(rawHeaders, out _);
            if (maximumHeaderCharacters < 1) { throw new ArgumentOutOfRangeException(nameof(maximumHeaderCharacters)); }
            if (rawHeaders.Length > maximumHeaderCharacters) { throw new ArgumentException("ARC header block exceeds the configured character limit.", nameof(rawHeaders)); }
            if (string.IsNullOrWhiteSpace(rawHeaders)) {
                logger?.WriteVerbose("No headers supplied for ARC analysis.");
                ChainState = ArcChainState.Missing;
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
                            ArcSealHeaders.Add(MessageHeaderValueParser.UnfoldRawValue(header));
                        } else if (header.Field.Equals("ARC-Authentication-Results", StringComparison.OrdinalIgnoreCase)) {
                            ArcAuthenticationResultsHeaders.Add(MessageHeaderValueParser.UnfoldRawValue(header));
                        } else if (header.Field.Equals("ARC-Message-Signature", StringComparison.OrdinalIgnoreCase)) {
                            ArcMessageSignatureHeaders.Add(MessageHeaderValueParser.UnfoldRawValue(header));
                        }
                    }
                }
            } catch (Exception ex) {
                StructureIssues.Add("ARC headers could not be parsed: " + ex.Message);
                logger?.WriteErrorCode(ArcCodes.ParseFailed, "Failed to parse ARC headers: {0}", ex.Message);
                ChainState = ArcChainState.Invalid;
                return;
            }

            ArcHeadersFound = ArcSealHeaders.Count > 0 ||
                              ArcAuthenticationResultsHeaders.Count > 0 || ArcMessageSignatureHeaders.Count > 0;

            if (!ArcHeadersFound) {
                ChainState = ArcChainState.Missing;
                return;
            }

            var groups = new Dictionary<int, Dictionary<string, List<string>>>();
            void Add(string kind, IEnumerable<string> values) {
                foreach (var value in values) {
                    var tags = ParseInstanceTags(kind, value, out var duplicateTags);
                    if (duplicateTags) { StructureIssues.Add(kind + " repeats a tag."); }
                    if (!tags.TryGetValue("i", out var instanceText) || !int.TryParse(instanceText, out var instance) || instance < 1 || instance > 50) {
                        StructureIssues.Add(kind + " has an invalid or out-of-range instance (1..50).");
                        continue;
                    }
                    if (!groups.TryGetValue(instance, out var instanceHeaders)) {
                        instanceHeaders = new Dictionary<string, List<string>>();
                        groups[instance] = instanceHeaders;
                    }
                    if (!instanceHeaders.TryGetValue(kind, out var list)) {
                        list = new List<string>();
                        instanceHeaders[kind] = list;
                    }
                    list.Add(value);
                }
            }
            Add("AS", ArcSealHeaders);
            Add("AMS", ArcMessageSignatureHeaders);
            Add("AAR", ArcAuthenticationResultsHeaders);
            SealsIncludeSignatures = ArcSealHeaders.Count > 0 && ArcSealHeaders.All(seal =>
                MessageHeaderValueParser.ParseTags(seal).TryGetValue("b", out var signature) && !string.IsNullOrWhiteSpace(signature));
            var top = groups.Count == 0 ? 0 : groups.Keys.Max();
            for (var instance = 1; instance <= top; instance++) {
                if (!groups.TryGetValue(instance, out var values)) {
                    StructureIssues.Add($"Missing ARC instance {instance}.");
                    continue;
                }
                var detail = new MessageArcInstance { Instance = instance };
                if (values.TryGetValue("AS", out var seals)) {
                    detail.Seal = seals[0];
                    var tags = MessageHeaderValueParser.ParseTags(detail.Seal);
                    detail.ChainValidation = tags.TryGetValue("cv", out var cv) ? cv : null;
                    detail.SealerDomain = tags.TryGetValue("d", out var domain) ? domain : null;
                }
                if (values.TryGetValue("AMS", out var signatures)) { detail.MessageSignature = signatures[0]; }
                if (values.TryGetValue("AAR", out var results)) {
                    detail.Authentication = MessageHeaderValueParser.ParseAuthentication("ARC-Authentication-Results", string.Join("; ", MessageHeaderValueParser.Split(results[0]).Skip(1)), instance);
                }
                Instances.Add(detail);
                foreach (var kind in new[] { "AS", "AMS", "AAR" }) {
                    if (!values.TryGetValue(kind, out var list) || list.Count != 1) {
                        StructureIssues.Add($"ARC instance {instance} requires exactly one {kind}.");
                        continue;
                    }
                    if (kind == "AAR") { continue; }
                    var tags = MessageHeaderValueParser.ParseTags(list[0]);
                    if (!tags.TryGetValue("b", out var signature) || string.IsNullOrWhiteSpace(signature)) {
                        StructureIssues.Add($"ARC instance {instance} {kind} has no signature value.");
                        if (kind == "AS") { SealsIncludeSignatures = false; }
                    }
                    if (kind == "AS") {
                        tags.TryGetValue("cv", out var cv);
                        bool failed = string.Equals(cv, "fail", StringComparison.OrdinalIgnoreCase);
                        if (failed) {
                            StructureIssues.Add($"ARC instance {instance} declares cv=fail.");
                        } else if ((instance == 1 && !string.Equals(cv, "none", StringComparison.OrdinalIgnoreCase)) ||
                            (instance > 1 && !string.Equals(cv, "pass", StringComparison.OrdinalIgnoreCase))) {
                            StructureIssues.Add($"ARC instance {instance} has an invalid cv value.");
                        }
                        ChainValidationFailed |= failed;
                    }
                }
            }
            ValidChain = StructureIssues.Count == 0 && top > 0;
            ChainState = ValidChain ? ArcChainState.Valid : ArcChainState.Invalid;
            if (ValidChain && _collector != null) {
                logger?.WriteInformationCode(ArcCodes.SealsIntact, "ARC seals contain signature values; cryptographic verification not performed");
                logger?.WriteInformationCode(ArcCodes.ChainValid, "ARC header structure is complete; cryptographic verification not performed");
            }
        }
        private static Dictionary<string, string> ParseInstanceTags(string kind, string value, out bool duplicateTags) {
            if (kind != "AAR") { return MessageHeaderValueParser.ParseTags(value, out duplicateTags); }
            var clauses = MessageHeaderValueParser.Split(value, stripComments: true);
            var tags = MessageHeaderValueParser.ParseTags(clauses[0], out duplicateTags);
            // AAR's remaining clauses are authentication methods, not a DKIM tag list.
            duplicateTags |= clauses.Skip(1).Any(clause => MessageHeaderValueParser.ParseTags(clause).ContainsKey("i"));
            return tags;
        }
        /// <summary>Structured assessments captured during ARC analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Actionable recommendations derived from assessments.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
    }
}
