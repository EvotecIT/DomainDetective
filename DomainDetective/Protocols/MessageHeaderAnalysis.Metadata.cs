using MimeKit;
using MimeKit.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DomainDetective;

public partial class MessageHeaderAnalysis {
    /// <summary>All original fields, retaining duplicates and signature metadata.</summary>
    public List<MessageHeaderField> Fields { get; } = new();
    /// <summary>Parsed From mailboxes.</summary>
    public List<MessageMailbox> FromAddresses { get; } = new();
    /// <summary>Parsed Reply-To mailboxes.</summary>
    public List<MessageMailbox> ReplyToAddresses { get; } = new();
    /// <summary>Parsed Return-Path mailboxes.</summary>
    public List<MessageMailbox> ReturnPathAddresses { get; } = new();
    /// <summary>DKIM metadata for every signature, including malformed ones.</summary>
    public List<MessageDkimSignature> DkimSignatures { get; } = new();
    /// <summary>ARC structure analysis, distinct from receiver-reported ARC and cryptographic verification.</summary>
    public ARCAnalysis ArcStructure { get; private set; } = new();
    /// <summary>Header findings suitable for console, report, or JSON consumers.</summary>
    public List<MessageHeaderFinding> Findings { get; } = new();
    /// <summary>Cryptographic outcomes populated only by full-message verification.</summary>
    public List<MessageSignatureVerification> SignatureVerification { get; } = new();
    /// <summary>Observed strict, relaxed, or absent SPF identity alignment; no policy is assumed.</summary>
    public string? SpfAlignment { get; private set; }
    /// <summary>Observed strict, relaxed, or absent DKIM alignment using passing receiver identities.</summary>
    public string? DkimAlignment { get; private set; }
    /// <summary>Mailing-list identifier.</summary>
    public string? ListId { get; private set; }
    /// <summary>List-Unsubscribe value. URLs are never fetched.</summary>
    public string? ListUnsubscribe { get; private set; }
    /// <summary>Whether the message advertises one-click unsubscribe; authentication is separate.</summary>
    public bool ListUnsubscribeOneClick { get; private set; }

    private void ResetMessageMetadata() {
        Source = null;
        _selectedAuthenticationEvidence.Clear();
        Findings.Clear();
        FromAddresses.Clear();
        ReplyToAddresses.Clear();
        ReturnPathAddresses.Clear();
        DkimSignatures.Clear();
        SignatureVerification.Clear();
        ArcStructure = new ARCAnalysis();
        SpfAlignment = null;
        DkimAlignment = null;
        ListId = null;
        ListUnsubscribe = null;
        ListUnsubscribeOneClick = false;
        ExchangeHeaders.Clear();
        DefenderVerdicts.Clear();
        DefenderVerdictMeanings.Clear();
        ExchangeAuthMechanism = null;
        ExchangeAuthMechanismMeaning = null;
        SpamAssassinScore = null;
        SpamAssassinTests = Array.Empty<string>();
        RspamdSymbols = Array.Empty<string>();
    }

    private void AnalyzeMessageMetadata() {
        Findings.Clear();
        FromAddresses.Clear();
        ReplyToAddresses.Clear();
        ReturnPathAddresses.Clear();
        DkimSignatures.Clear();
        ParseMailboxes(From, FromAddresses);
        ParseMailboxes(GetHeaderValue("Reply-To"), ReplyToAddresses);
        ParseMailboxes(GetHeaderValue("Return-Path"), ReturnPathAddresses);
        if (Subject != null) { Subject = Rfc2047.DecodeText(Encoding.UTF8.GetBytes(Subject)); }
        ArcStructure = new ARCAnalysis();
        ArcStructure.Analyze(RawHeaders ?? string.Empty, maximumHeaderCharacters: _headerOptions.MaximumHeaderCharacters);
        ListId = GetHeaderValue("List-Id");
        ListUnsubscribe = GetHeaderValue("List-Unsubscribe");
        ListUnsubscribeOneClick = !DuplicateHeaders.ContainsKey("List-Unsubscribe") && !DuplicateHeaders.ContainsKey("List-Unsubscribe-Post")
            && string.Equals(GetHeaderValue("List-Unsubscribe-Post")?.Trim(), "List-Unsubscribe=One-Click", StringComparison.OrdinalIgnoreCase)
            && HasOneHttpsUnsubscribeTarget(ListUnsubscribe);
        var singleton = new HashSet<string>(new[] { "From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "Return-Path", "In-Reply-To", "References" }, StringComparer.OrdinalIgnoreCase);
        foreach (var field in DuplicateHeaders.Keys.Where(singleton.Contains)) {
            AddFinding("HEADERS.Field.Duplicate", AssessmentSeverity.Warning, $"Singleton field {field} occurs {DuplicateHeaders[field].Count} times; clients can select different values.");
        }
        foreach (var field in Fields) {
            if (field.Value.Any(IsDirectionControl) || Rfc2047.DecodeText(Encoding.UTF8.GetBytes(field.Value)).Any(IsDirectionControl)) {
                AddFinding("HEADERS.Unicode.DirectionControl", AssessmentSeverity.Warning, $"Field {field.Name} contains Unicode direction controls; display their code points when reporting.");
            }
        }
        if (AuthenticationConflict) { AddFinding("HEADERS.Auth.Conflict", AssessmentSeverity.Warning, "Selected authentication observations conflict or repeat identity properties; gateway sanitization and result provenance require review."); }
        if (AuthenticationTrust != MessageAuthenticationTrust.Configured) {
            AddFinding("HEADERS.Auth.Unverified", AssessmentSeverity.Info, "Authentication results are receiver-reported claims. Route matching and header order do not prove their writer; configure exact trusted identifiers and gateway sanitization.");
        }
        if (_headerOptions.TrustedAuthServIds.Length > 0 && AuthenticationTrust != MessageAuthenticationTrust.Configured) {
            AddFinding("HEADERS.Auth.NoConfiguredMatch", AssessmentSeverity.Warning, "No authentication result matches the configured gateway identifiers.");
        }
        if (HasClockSkew) { AddFinding("HEADERS.Route.ClockSkew", AssessmentSeverity.Info, "At least one adjacent route timestamp decreases; delays are approximate and route order is preserved."); }
        if (OmittedReceivedHops > 0) { AddFinding("HEADERS.Route.Truncated", AssessmentSeverity.Warning, $"{OmittedReceivedHops} Received fields were omitted by the configured hop limit; route analysis is incomplete."); }
        if (ArcStructure.ChainState == ArcChainState.Invalid) { AddFinding("HEADERS.ARC.Structure", AssessmentSeverity.Warning, string.Join(" ", ArcStructure.StructureIssues)); }
        if (ReplyToAddresses.Any(reply => FromAddresses.Count > 0 && FromAddresses.All(from => !string.Equals(from.Domain, reply.Domain, StringComparison.OrdinalIgnoreCase)))) {
            AddFinding("HEADERS.Identity.ReplyToMismatch", AssessmentSeverity.Info, "Reply-To uses a different domain from From; legitimate forwarding and newsletters also do this.");
        }
        AnalyzeDkimMetadata();
        AnalyzeForwardingWitness();
        AnalyzeAlignment();
        AnalyzeVendorMetadata();
    }

    private void AnalyzeForwardingWitness() {
        if (AuthenticationTrust != MessageAuthenticationTrust.Configured || ArcResult != "pass" || !ArcStructure.ValidChain || ArcStructure.ChainValidationFailed) { return; }
        foreach (var signature in DkimSignatures.Where(signature => signature.ReceiverResult == "fail" && !string.IsNullOrWhiteSpace(signature.Domain))) {
            if (ArcStructure.Instances.Any(instance => instance.Authentication?.Methods.Any(method => method.Method == "dkim" && method.Result == "pass"
                && string.Equals(GetIdentity(method, "header.d"), signature.Domain, StringComparison.OrdinalIgnoreCase)) == true)) {
                AddFinding("HEADERS.DKIM.ForwardingWitness", AssessmentSeverity.Info, "A configured receiver reports ARC pass and the ARC history claims an earlier DKIM pass for " + signature.Domain + ". Forwarding may explain the reported DKIM failure; local cryptographic results and sealer trust remain separate.");
            }
        }
    }

    private void AnalyzeDkimMetadata() {
        foreach (var field in Fields.Where(field => field.Name.Equals("DKIM-Signature", StringComparison.OrdinalIgnoreCase))) {
            var tags = MessageHeaderValueParser.ParseTags(field.Value, out var duplicateTags);
            if (duplicateTags) { AddFinding("HEADERS.DKIM.DuplicateTag", AssessmentSeverity.Warning, "A DKIM signature repeats a tag; its metadata is ambiguous and cryptographic verification is required."); }
            string? Tag(string key) => tags.TryGetValue(key, out var value) ? value : null;
            var signature = new MessageDkimSignature {
                Raw = field.Value, Tags = tags, Domain = Tag("d"), Selector = Tag("s"), Algorithm = Tag("a"), Canonicalization = Tag("c"),
                SignedHeaders = (Tag("h") ?? string.Empty).Split(':').Select(value => value.Trim().ToLowerInvariant()).Where(value => value.Length > 0).ToArray(),
                Timestamp = ParseUnixTime(Tag("t")), Expires = ParseUnixTime(Tag("x")),
                BodyLength = long.TryParse(Tag("l"), out var length) && length >= 0 ? length : null
            };
            var results = _selectedAuthenticationEvidence.SelectMany(value => value.Methods).Where(method => method.Method == "dkim"
                && string.Equals(GetIdentity(method, "header.d"), signature.Domain, StringComparison.OrdinalIgnoreCase)
                && (!method.Properties.ContainsKey("header.s") || string.Equals(GetIdentity(method, "header.s"), signature.Selector, StringComparison.OrdinalIgnoreCase)))
                .Select(method => method.Result).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            signature.ReceiverResult = results.Length > 1 ? "conflict" : results.FirstOrDefault();
            DkimSignatures.Add(signature);
            if (string.Equals(signature.Algorithm, "rsa-sha1", StringComparison.OrdinalIgnoreCase)) { AddFinding("HEADERS.DKIM.WeakHash", AssessmentSeverity.Warning, "DKIM uses deprecated SHA-1."); }
            if (signature.BodyLength.HasValue) { AddFinding("HEADERS.DKIM.BodyLength", AssessmentSeverity.Warning, "DKIM l= limits the signed body; appended content may be outside the signature."); }
            if (signature.Expires < DateTimeOffset.UtcNow) { AddFinding("HEADERS.DKIM.Expired", AssessmentSeverity.Info, "A DKIM signature is expired at analysis time; this does not establish its validity at delivery."); }
            if (!signature.SignedHeaders.Contains("from")) { AddFinding("HEADERS.DKIM.FromUnsigned", AssessmentSeverity.Warning, "A DKIM signature does not include From in h=."); }
        }
    }

    private void AnalyzeAlignment() {
        var from = FromAddresses.Count == 1 && !DuplicateHeaders.ContainsKey("From") ? FromAddresses[0].Domain : null;
        var spf = SpfEvidence?.Methods.FirstOrDefault(method => method.Method == "spf");
        var envelope = spf == null ? (DuplicateHeaders.ContainsKey("Return-Path") ? null : ReturnPathAddresses.FirstOrDefault()?.Domain) : AddressDomain(GetIdentity(spf, "smtp.mailfrom"));
        if (spf != null && string.IsNullOrEmpty(envelope)
            && (spf.Properties.ContainsKey("smtp.mailfrom") || GetHeaderValue("Return-Path")?.Trim() == "<>")) {
            envelope = AddressDomain(GetIdentity(spf, "smtp.helo"));
            if (string.IsNullOrEmpty(envelope)) { envelope = AddressDomain(GetIdentity(spf, "helo")); }
        }
        var spfMethods = _selectedAuthenticationEvidence.SelectMany(value => value.Methods).Where(method => method.Method == "spf");
        var spfConflict = spf != null && spfMethods.Where(method => string.Equals(AuthenticationIdentity(method), AuthenticationIdentity(spf), StringComparison.OrdinalIgnoreCase))
            .Select(method => method.Result).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1;
        SpfAlignment = spfConflict || spf?.DuplicateProperties.Count > 0 ? null : Alignment(from, envelope);
        var dkimMethods = _selectedAuthenticationEvidence.SelectMany(value => value.Methods).Where(method => method.Method == "dkim").ToArray();
        var conflicts = ConflictingDkimObservations(dkimMethods);
        var dkimDomains = dkimMethods.Where(method => method.Result == "pass" && method.DuplicateProperties.Count == 0 && !conflicts.Contains(method))
            .Select(method => GetIdentity(method, "header.d")).ToArray();
        var alignments = dkimDomains.Select(domain => Alignment(from, domain)).ToArray();
        DkimAlignment = alignments.Contains("Strict") ? "Strict" : alignments.Contains("Relaxed") ? "Relaxed" : alignments.Contains("None") ? "None" : null;
        if (SpfAlignment == "None") { AddFinding("HEADERS.SPF.NotAligned", AssessmentSeverity.Info, "The reported envelope identity is not aligned with From; SPF cannot contribute to DMARC for this identity."); }
        if (SpfEvidence?.HeaderName == "Received-SPF") { AddFinding("HEADERS.SPF.ReceivedSpfFallback", AssessmentSeverity.Info, "SPF is reported by a Received-SPF field; review that field's separate writer and provenance."); }
    }

    private static readonly Lazy<PublicSuffixList> HeaderSuffixList = new(() => {
        using var stream = typeof(MessageHeaderAnalysis).Assembly.GetManifestResourceStream("DomainDetective.public_suffix_list.dat");
        return stream == null ? throw new InvalidOperationException("Bundled public suffix data is unavailable.") : PublicSuffixList.Load(stream);
    });

    private static string? Alignment(string? from, string? other) {
        if (string.IsNullOrWhiteSpace(from) || string.IsNullOrWhiteSpace(other)) { return null; }
        try {
            var first = Helpers.DomainHelper.ValidateIdn(from!);
            var second = Helpers.DomainHelper.ValidateIdn(other!);
            if (HeaderSuffixList.Value.IsPublicSuffix(first) || HeaderSuffixList.Value.IsPublicSuffix(second)) { return null; }
            if (string.Equals(first, second, StringComparison.OrdinalIgnoreCase)) { return "Strict"; }
            return string.Equals(HeaderSuffixList.Value.GetRegistrableDomain(first), HeaderSuffixList.Value.GetRegistrableDomain(second), StringComparison.OrdinalIgnoreCase) ? "Relaxed" : "None";
        } catch (ArgumentException) { return null; }
    }

    private static string? AddressDomain(string? value) {
        if (string.IsNullOrWhiteSpace(value)) { return null; }
        var at = value!.LastIndexOf('@');
        return (at >= 0 ? value.Substring(at + 1) : value).Trim('<', '>');
    }

    private static bool HasOneHttpsUnsubscribeTarget(string? value) {
        if (string.IsNullOrWhiteSpace(value)) { return false; }
        var target = new StringBuilder();
        var inTarget = false;
        var commentDepth = 0;
        var escaped = false;
        var httpsTargets = 0;
        foreach (var ch in value!) {
            if (inTarget) {
                if (ch == '<') { return false; }
                if (ch != '>') {
                    // RFC 2369 tolerates MTA-inserted whitespace within URI brackets.
                    if (!char.IsWhiteSpace(ch)) { target.Append(ch); }
                    continue;
                }
                if (!Uri.TryCreate(target.ToString(), UriKind.Absolute, out var uri) || !uri.IsWellFormedOriginalString()) { return false; }
                if (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) && uri.Host.Length > 0) { httpsTargets++; }
                target.Clear();
                inTarget = false;
            } else if (commentDepth > 0) {
                if (escaped) { escaped = false; continue; }
                if (ch == '\\') { escaped = true; }
                else if (ch == '(') { commentDepth++; }
                else if (ch == ')') { commentDepth--; }
            } else if (ch == '(') { commentDepth++; }
            else if (ch == '<') { inTarget = true; }
            else if (!char.IsWhiteSpace(ch) && ch != ',') { return false; }
        }
        return !inTarget && commentDepth == 0 && httpsTargets == 1;
    }

    private static void ParseMailboxes(string? value, List<MessageMailbox> target) {
        if (InternetAddressList.TryParse(value ?? string.Empty, out var addresses)) {
            foreach (var address in addresses.Mailboxes) { target.Add(new MessageMailbox { Name = address.Name ?? string.Empty, Address = address.Address, Domain = AddressDomain(address.Address) ?? string.Empty }); }
        }
    }

    private static DateTimeOffset? ParseUnixTime(string? value) {
        if (!long.TryParse(value, out var seconds)) { return null; }
        try { return DateTimeOffset.FromUnixTimeSeconds(seconds); } catch (ArgumentOutOfRangeException) { return null; }
    }

    internal static bool IsDirectionControl(char value) => value == '\u061c' || value == '\u200e' || value == '\u200f' || (value >= '\u202a' && value <= '\u202e') || (value >= '\u2066' && value <= '\u2069');

    private void AddFinding(string code, AssessmentSeverity severity, string message) {
        Findings.Add(new MessageHeaderFinding { Code = code, Severity = severity, Message = message });
        Assessments.Add(new Assessment { Code = code, Severity = severity, Category = "HEADERS", Message = message, Timestamp = DateTimeOffset.UtcNow });
    }
}
