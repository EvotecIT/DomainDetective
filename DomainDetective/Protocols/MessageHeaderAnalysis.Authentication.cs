using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class MessageHeaderAnalysis {
    private MessageHeaderAnalysisOptions _headerOptions = new();
    private int _receivedHeadersEvaluated;
    private readonly List<MessageAuthenticationEvidence> _selectedAuthenticationEvidence = new();
    private readonly HashSet<string> _conflictedAuthenticationMethods = new(StringComparer.OrdinalIgnoreCase);
    private bool _dmarcIdentityMismatch;

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
    public bool HadBody { get; internal set; }
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
            hadBody = end + (end == lfEnd ? 2 : 4) < text.Length;
            return text.Substring(0, end) + "\r\n\r\n";
        }
        return text;
    }

    private void SelectAuthenticationEvidence() {
        CompAuthResult = null;
        CompAuthReason = null;
        AuthenticationConflict = false;
        _conflictedAuthenticationMethods.Clear();
        _dmarcIdentityMismatch = false;
        AuthenticationTrust = MessageAuthenticationTrust.None;
        AuthServId = null;
        SpfEvidence = null;
        _selectedAuthenticationEvidence.Clear();
        var trusted = new HashSet<string>(_headerOptions.TrustedAuthServIds.Select(NormalizeIdentity), StringComparer.OrdinalIgnoreCase);
        foreach (var observation in AuthenticationResults) {
            var id = NormalizeIdentity(observation.AuthServId);
            if (observation.HeaderName.Equals("Authentication-Results-Original", StringComparison.OrdinalIgnoreCase)) {
                // A preserved original is evidence of an earlier claim, not a result
                // authored by the configured receiver at this delivery boundary.
                observation.Trust = id.Length == 0 ? MessageAuthenticationTrust.Absent : MessageAuthenticationTrust.Unverified;
                continue;
            }
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
            var first = AuthenticationResults.FirstOrDefault(value => value.Methods.Count > 0 && value.HeaderName.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase));
            if (first != null) { selected.Add(first); }
        }
        var primary = selected.FirstOrDefault();
        _selectedAuthenticationEvidence.AddRange(selected);
        if (primary != null) {
            AuthServId = primary.AuthServId;
            AuthenticationTrust = primary.Trust;
        }
        var methods = selected.SelectMany(value => value.Methods).ToList();
        if (!methods.Any(method => method.Method == "spf")) {
            var fallback = AuthenticationResults.Where(value => value.HeaderName == "Received-SPF" && value.Methods.Count > 0 && value.Trust == MessageAuthenticationTrust.Configured).ToList();
            if (fallback.Count == 0 && AuthenticationTrust != MessageAuthenticationTrust.Configured) {
                var first = AuthenticationResults.FirstOrDefault(value => value.HeaderName == "Received-SPF" && value.Methods.Count > 0);
                if (first != null) { fallback.Add(first); }
            }
            _selectedAuthenticationEvidence.AddRange(fallback);
            methods.AddRange(fallback.SelectMany(value => value.Methods));
            if (primary == null && fallback.Count > 0) { AuthServId = fallback[0].AuthServId; AuthenticationTrust = fallback[0].Trust; }
        }
        foreach (var method in methods.Where(method => method.DuplicateProperties.Count > 0)) {
            _conflictedAuthenticationMethods.Add(method.Method);
        }
        foreach (var group in methods.GroupBy(AuthenticationIdentity, StringComparer.OrdinalIgnoreCase)) {
            if (group.Select(value => value.Result).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1) {
                _conflictedAuthenticationMethods.Add(group.First().Method);
            }
        }
        if (ConflictingDkimObservations(methods.Where(method => method.Method == "dkim")).Count > 0) {
            _conflictedAuthenticationMethods.Add("dkim");
        }
        var anyAuthenticationConflict = _conflictedAuthenticationMethods.Count > 0;
        // DMARC only describes the RFC5322.From identity. An unrelated header.from
        // must remain in raw evidence without controlling this message's outcome.
        var dmarcMethods = SelectDmarcMethods(methods);
        _conflictedAuthenticationMethods.Remove("dmarc");
        if (dmarcMethods.Any(method => method.DuplicateProperties.Count > 0)
            || dmarcMethods.Select(method => method.Result).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1) {
            _conflictedAuthenticationMethods.Add("dmarc");
        }
        AuthenticationConflict = anyAuthenticationConflict || _conflictedAuthenticationMethods.Count > 0;
        string? Result(string name) {
            var method = methods.FirstOrDefault(value => value.Method.Equals(name, StringComparison.OrdinalIgnoreCase));
            return HasAuthenticationConflict(name) ? "ambiguous" : method?.Result;
        }
        DkimResult = Result("dkim");
        SpfResult = Result("spf");
        SpfEvidence = _selectedAuthenticationEvidence.FirstOrDefault(value => value.Methods.Any(method => method.Method == "spf"));
        DmarcResult = HasAuthenticationConflict("dmarc") ? "ambiguous" : dmarcMethods.FirstOrDefault()?.Result;
        ArcResult = Result("arc");
        CompAuthResult = Result("compauth");
        var compauth = methods.FirstOrDefault(value => value.Method == "compauth");
        CompAuthReason = compauth == null ? null : GetIdentity(compauth, "reason");
        _hasTrustedAuthenticationResults = primary != null;
        _trustedDkimResult = DkimResult;
        _trustedSpfResult = SpfResult;
        _trustedDmarcResult = DmarcResult;
    }

    private static string GetIdentity(MessageAuthenticationMethod method, string property) => method.DuplicateProperties.Count == 0 && method.Properties.TryGetValue(property, out var value) ? value : string.Empty;
    private bool HasAuthenticationConflict(string method) => _conflictedAuthenticationMethods.Contains(method);
    private List<MessageAuthenticationMethod> SelectDmarcMethods(List<MessageAuthenticationMethod> methods) {
        var dmarc = methods.Where(method => method.Method == "dmarc").ToList();
        if (DuplicateHeaders.ContainsKey("From") || !TryGetDomain(From, out var fromDomain)) { return new List<MessageAuthenticationMethod>(); }
        var actualDomain = NormalizeDomainIdentity(fromDomain);
        if (actualDomain.Length == 0) { return new List<MessageAuthenticationMethod>(); }
        var matching = new List<MessageAuthenticationMethod>();
        var unspecified = new List<MessageAuthenticationMethod>();
        foreach (var method in dmarc) {
            if (method.DuplicateProperties.Count > 0) { continue; }
            if (!method.Properties.TryGetValue("header.from", out var reportedDomain)) {
                unspecified.Add(method);
            } else if (string.Equals(NormalizeDomainIdentity(reportedDomain), actualDomain, StringComparison.OrdinalIgnoreCase)) {
                matching.Add(method);
            } else {
                _dmarcIdentityMismatch = true;
            }
        }
        if (matching.Count == 0 && _dmarcIdentityMismatch) { return new List<MessageAuthenticationMethod>(); }
        matching.AddRange(unspecified);
        return matching;
    }
    private static string NormalizeDomainIdentity(string? value) {
        if (string.IsNullOrWhiteSpace(value)) { return string.Empty; }
        try { return Helpers.DomainHelper.ValidateIdn(value!).ToLowerInvariant(); }
        catch (ArgumentException) { return string.Empty; }
    }
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
        (method.Method == "spf" ? SpfIdentity(method)
        : method.Method == "dmarc" ? GetIdentity(method, "header.from")
        : GetIdentity(method, "header.d") + ":" + GetIdentity(method, "header.s"));
    private static string NormalizeIdentity(string? value) => (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
    private static string SpfIdentity(MessageAuthenticationMethod method) {
        var mailfrom = GetIdentity(method, "smtp.mailfrom").Trim('<', '>');
        return mailfrom.Length > 0 ? "mailfrom:" + mailfrom : "helo:" + GetIdentity(method, "smtp.helo");
    }
}
