using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class MessageHeaderAnalysis {
    private MessageHeaderAnalysisOptions _headerOptions = new();
    private int _receivedHeadersEvaluated;
    private readonly List<MessageAuthenticationEvidence> _selectedAuthenticationEvidence = new();

    /// <summary>All receiver-reported authentication observations with their provenance.</summary>
    public List<MessageAuthenticationEvidence> AuthenticationResults { get; } = new();
    /// <summary>Provenance of the selected summary. Configured trust depends on gateway sanitization.</summary>
    public MessageAuthenticationTrust AuthenticationTrust { get; private set; }
    /// <summary>Writer identifier of the selected summary, if present.</summary>
    public string? AuthServId { get; private set; }
    /// <summary>Selected SPF evidence, including its own provenance when Received-SPF supplies a fallback.</summary>
    public MessageAuthenticationEvidence? SpfEvidence { get; private set; }
    /// <summary>Receiver-reported Microsoft composite authentication result.</summary>
    public string? CompAuthResult { get; private set; }
    /// <summary>Microsoft composite authentication reason code as supplied.</summary>
    public string? CompAuthReason { get; private set; }
    /// <summary>Documented meaning of the reported composite-authentication reason.</summary>
    public string? CompAuthReasonMeaning => MessageVendorMeanings.CompositeReason(CompAuthReason);
    /// <summary>Whether adjacent route timestamps decrease in delivery order.</summary>
    public bool HasClockSkew { get; private set; }
    /// <summary>Received fields omitted due to the configured resource limit.</summary>
    public int OmittedReceivedHops => Math.Max(0, _receivedHeadersEvaluated - ReceivedHops.Count);
    /// <summary>Whether any body followed the supplied header block. The body is not analyzed by Parse.</summary>
    public bool HadBody { get; private set; }
    /// <summary>Local input filename when analysis originated from a file.</summary>
    public string? Source { get; set; }
    /// <summary>Whether the selected configured results disagree about the same authentication identity.</summary>
    public bool AuthenticationConflict { get; private set; }

    private string ExtractHeaderBlock(string text) {
        var headers = ExtractMessageHeaderBlock(text, out var hadBody);
        HadBody = hadBody;
        return headers;
    }

    internal static string ExtractMessageHeaderBlock(string text, out bool hadBody) {
        hadBody = false;
        text = (text ?? string.Empty).TrimStart('\uFEFF');
        var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var lfEnd = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (lfEnd >= 0 && (end < 0 || lfEnd < end)) { end = lfEnd; }
        if (end >= 0) {
            hadBody = true;
            return text.Substring(0, end) + "\r\n\r\n";
        }
        return text;
    }

    private void SelectAuthenticationEvidence() {
        CompAuthResult = null;
        CompAuthReason = null;
        AuthenticationConflict = false;
        AuthenticationTrust = MessageAuthenticationTrust.None;
        AuthServId = null;
        SpfEvidence = null;
        _selectedAuthenticationEvidence.Clear();
        var trusted = new HashSet<string>(_headerOptions.TrustedAuthServIds.Select(NormalizeIdentity), StringComparer.OrdinalIgnoreCase);
        foreach (var observation in AuthenticationResults) {
            var id = NormalizeIdentity(observation.AuthServId);
            observation.Trust = id.Length == 0 ? MessageAuthenticationTrust.Absent
                : trusted.Contains(id) ? MessageAuthenticationTrust.Configured
                : ReceivedHops.Any(hop => string.Equals(id, NormalizeIdentity(hop.ByHost), StringComparison.OrdinalIgnoreCase))
                    ? MessageAuthenticationTrust.RouteMatched : MessageAuthenticationTrust.Unverified;
        }
        // Prefer explicit trust, then the topmost normal receiver observation. Route matches
        // are informational and never promote attacker-provided lower headers to authority.
        var selected = AuthenticationResults.Where(value => value.Methods.Count > 0 && value.Trust == MessageAuthenticationTrust.Configured
            && value.HeaderName.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase)).ToList();
        if (selected.Count == 0) {
            var first = AuthenticationResults.FirstOrDefault(value => value.Methods.Count > 0 && value.HeaderName.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase))
                ?? AuthenticationResults.FirstOrDefault(value => value.Methods.Count > 0 && value.HeaderName != "Received-SPF");
            if (first != null) { selected.Add(first); }
        }
        var primary = selected.FirstOrDefault();
        _selectedAuthenticationEvidence.AddRange(selected);
        if (primary != null) {
            AuthServId = primary.AuthServId;
            AuthenticationTrust = primary.Trust;
        }
        var methods = selected.SelectMany(value => value.Methods).ToList();
        foreach (var group in methods.GroupBy(AuthenticationIdentity, StringComparer.OrdinalIgnoreCase)) {
            if (group.Select(value => value.Result).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1) { AuthenticationConflict = true; }
        }
        AuthenticationConflict |= ConflictingDkimObservations(methods.Where(method => method.Method == "dkim")).Count > 0;
        string? Result(string name) => methods.FirstOrDefault(value => value.Method.Equals(name, StringComparison.OrdinalIgnoreCase))?.Result;
        DkimResult = Result("dkim");
        SpfResult = Result("spf");
        SpfEvidence = selected.FirstOrDefault(value => value.Methods.Any(method => method.Method == "spf"));
        if (SpfResult == null) {
            var fallback = AuthenticationResults.FirstOrDefault(value => value.HeaderName == "Received-SPF" && value.Methods.Count > 0 && value.Trust == MessageAuthenticationTrust.Configured)
                ?? (AuthenticationTrust != MessageAuthenticationTrust.Configured ? AuthenticationResults.FirstOrDefault(value => value.HeaderName == "Received-SPF" && value.Methods.Count > 0) : null);
            if (fallback != null) {
                SpfEvidence = fallback;
                SpfResult = fallback.Methods[0].Result;
                if (primary == null) { AuthServId = fallback.AuthServId; AuthenticationTrust = fallback.Trust; }
            }
        }
        DmarcResult = Result("dmarc");
        ArcResult = Result("arc");
        CompAuthResult = Result("compauth");
        var compauth = methods.FirstOrDefault(value => value.Method == "compauth");
        CompAuthReason = compauth == null ? null : GetIdentity(compauth, "reason");
        _hasTrustedAuthenticationResults = primary != null;
        _trustedDkimResult = DkimResult;
        _trustedSpfResult = SpfResult;
        _trustedDmarcResult = DmarcResult;
    }

    private static string GetIdentity(MessageAuthenticationMethod method, string property) => method.Properties.TryGetValue(property, out var value) ? value : string.Empty;
    private static HashSet<MessageAuthenticationMethod> ConflictingDkimObservations(IEnumerable<MessageAuthenticationMethod> methods) {
        var conflicts = new HashSet<MessageAuthenticationMethod>();
        foreach (var domain in methods.GroupBy(method => GetIdentity(method, "header.d"), StringComparer.OrdinalIgnoreCase)) {
            var domainResults = domain.Select(method => method.Result).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var unspecifiedResults = domain.Where(method => GetIdentity(method, "header.s").Length == 0)
                .Select(method => method.Result).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            foreach (var selector in domain.GroupBy(method => GetIdentity(method, "header.s"), StringComparer.OrdinalIgnoreCase)) {
                // An omitted selector can refer to any signature from this domain.
                var results = selector.Key.Length == 0 ? domainResults
                    : selector.Select(method => method.Result).Concat(unspecifiedResults).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                if (results.Length > 1) { foreach (var method in selector) { conflicts.Add(method); } }
            }
        }
        return conflicts;
    }
    private static string AuthenticationIdentity(MessageAuthenticationMethod method) => method.Method + ":" +
        (method.Method == "spf" ? GetIdentity(method, "smtp.mailfrom") + ":" + GetIdentity(method, "smtp.helo")
        : method.Method == "dmarc" ? GetIdentity(method, "header.from")
        : GetIdentity(method, "header.d") + ":" + GetIdentity(method, "header.s"));
    private static string NormalizeIdentity(string? value) => (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
}
