using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Text.Json.Serialization;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateOverride {
    [JsonPropertyName("match")]
    public DesiredStateMatch Match { get; set; } = new DesiredStateMatch();

    [JsonPropertyName("profile")]
    public DesiredStateProfile Profile { get; set; } = new DesiredStateProfile();

    public bool Matches(string domain, MailDomainClassificationCategory? classification)
        => Match != null && Match.Matches(domain, classification);
}

public sealed class DesiredStateMatch {
    [JsonPropertyName("domainPatterns")]
    public string[]? DomainPatterns { get; set; }

    [JsonPropertyName("classifications")]
    public MailDomainClassificationCategory[]? Classifications { get; set; }

    public bool Matches(string domain, MailDomainClassificationCategory? classification) {
        if (string.IsNullOrWhiteSpace(domain)) return false;

        if (Classifications != null && Classifications.Length > 0) {
            if (!classification.HasValue) return false;
            if (!Classifications.Contains(classification.Value)) return false;
        }

        if (DomainPatterns == null || DomainPatterns.Length == 0) return true;

        foreach (var pattern in DomainPatterns) {
            if (string.IsNullOrWhiteSpace(pattern)) continue;
            if (WildcardMatcher.IsMatch(domain, pattern)) return true;
        }
        return false;
    }
}

public sealed class DesiredStateProfile {
    [JsonPropertyName("checks")]
    public HealthCheckType[]? Checks { get; set; }

    [JsonPropertyName("assessmentPolicy")]
    public DesiredStateAssessmentPolicy? AssessmentPolicy { get; set; }

    [JsonPropertyName("dmarc")]
    public DesiredStateDmarcPolicy? Dmarc { get; set; }

    [JsonPropertyName("spf")]
    public DesiredStateSpfPolicy? Spf { get; set; }

    [JsonPropertyName("dkim")]
    public DesiredStateDkimPolicy? Dkim { get; set; }

    [JsonPropertyName("mtasts")]
    public DesiredStateMtastsPolicy? Mtasts { get; set; }

    [JsonPropertyName("tlsrpt")]
    public DesiredStateTlsRptPolicy? TlsRpt { get; set; }

    [JsonPropertyName("bimi")]
    public DesiredStateBimiPolicy? Bimi { get; set; }

    [JsonPropertyName("mx")]
    public DesiredStateMxPolicy? Mx { get; set; }

    [JsonPropertyName("startTls")]
    public DesiredStateStartTlsPolicy? StartTls { get; set; }

    [JsonPropertyName("smtpTls")]
    public DesiredStateMailTlsPolicy? SmtpTls { get; set; }

    [JsonPropertyName("imapTls")]
    public DesiredStateMailTlsPolicy? ImapTls { get; set; }

    [JsonPropertyName("pop3Tls")]
    public DesiredStateMailTlsPolicy? Pop3Tls { get; set; }

    [JsonPropertyName("smtpBanner")]
    public DesiredStateSmtpBannerPolicy? SmtpBanner { get; set; }

    [JsonPropertyName("smtpAuth")]
    public DesiredStateSmtpAuthPolicy? SmtpAuth { get; set; }

    [JsonPropertyName("openRelay")]
    public DesiredStateOpenRelayPolicy? OpenRelay { get; set; }

    [JsonPropertyName("openResolver")]
    public DesiredStateOpenResolverPolicy? OpenResolver { get; set; }

    [JsonPropertyName("mailLatency")]
    public DesiredStateMailLatencyPolicy? MailLatency { get; set; }

    [JsonPropertyName("autodiscover")]
    public DesiredStateAutodiscoverPolicy? Autodiscover { get; set; }

    [JsonPropertyName("reverseDns")]
    public DesiredStateReverseDnsPolicy? ReverseDns { get; set; }

    [JsonPropertyName("fcrDns")]
    public DesiredStateFcrDnsPolicy? FcrDns { get; set; }

    [JsonPropertyName("ns")]
    public DesiredStateNsPolicy? Ns { get; set; }

    [JsonPropertyName("danglingCname")]
    public DesiredStateDanglingCnamePolicy? DanglingCname { get; set; }

    [JsonPropertyName("caa")]
    public DesiredStateCaaPolicy? Caa { get; set; }

    [JsonPropertyName("dnssec")]
    public DesiredStateDnssecPolicy? DnsSec { get; set; }

    [JsonPropertyName("soa")]
    public DesiredStateSoaPolicy? Soa { get; set; }

    [JsonPropertyName("dane")]
    public DesiredStateDanePolicy? Dane { get; set; }

    [JsonPropertyName("dnsbl")]
    public DesiredStateDnsblPolicy? Dnsbl { get; set; }

    [JsonPropertyName("dnsHealth")]
    public DesiredStateDnsHealthPolicy? DnsHealth { get; set; }

    [JsonPropertyName("apexAddress")]
    public DesiredStateApexAddressPolicy? ApexAddress { get; set; }

    [JsonPropertyName("rpki")]
    public DesiredStateRpkiPolicy? Rpki { get; set; }

    [JsonPropertyName("ednsSupport")]
    public DesiredStateEdnsSupportPolicy? EdnsSupport { get; set; }

    [JsonPropertyName("dnsOverTls")]
    public DesiredStateDnsOverTlsPolicy? DnsOverTls { get; set; }

    [JsonPropertyName("flatteningService")]
    public DesiredStateFlatteningServicePolicy? FlatteningService { get; set; }

    [JsonPropertyName("delegation")]
    public DesiredStateDelegationPolicy? Delegation { get; set; }

    [JsonPropertyName("zoneTransfer")]
    public DesiredStateZoneTransferPolicy? ZoneTransfer { get; set; }

    [JsonPropertyName("wildcardDns")]
    public DesiredStateWildcardDnsPolicy? WildcardDns { get; set; }

    [JsonPropertyName("ttl")]
    public DesiredStateTtlPolicy? Ttl { get; set; }

    [JsonPropertyName("securityTxt")]
    public DesiredStateSecurityTxtPolicy? SecurityTxt { get; set; }

    [JsonPropertyName("robots")]
    public DesiredStateRobotsPolicy? Robots { get; set; }

    public DesiredStateProfile Clone() {
        return new DesiredStateProfile {
            Checks = Checks?.ToArray(),
            AssessmentPolicy = AssessmentPolicy?.Clone(),
            Dmarc = Dmarc?.Clone(),
            Spf = Spf?.Clone(),
            Dkim = Dkim?.Clone(),
            Mtasts = Mtasts?.Clone(),
            TlsRpt = TlsRpt?.Clone(),
            Bimi = Bimi?.Clone(),
            Mx = Mx?.Clone(),
            StartTls = StartTls?.Clone(),
            SmtpTls = SmtpTls?.Clone(),
            ImapTls = ImapTls?.Clone(),
            Pop3Tls = Pop3Tls?.Clone(),
            SmtpBanner = SmtpBanner?.Clone(),
            SmtpAuth = SmtpAuth?.Clone(),
            OpenRelay = OpenRelay?.Clone(),
            OpenResolver = OpenResolver?.Clone(),
            MailLatency = MailLatency?.Clone(),
            Autodiscover = Autodiscover?.Clone(),
            ReverseDns = ReverseDns?.Clone(),
            FcrDns = FcrDns?.Clone(),
            Ns = Ns?.Clone(),
            DanglingCname = DanglingCname?.Clone(),
            Caa = Caa?.Clone(),
            DnsSec = DnsSec?.Clone(),
            Soa = Soa?.Clone(),
            Dane = Dane?.Clone(),
            Dnsbl = Dnsbl?.Clone(),
            DnsHealth = DnsHealth?.Clone(),
            ApexAddress = ApexAddress?.Clone(),
            Rpki = Rpki?.Clone(),
            EdnsSupport = EdnsSupport?.Clone(),
            DnsOverTls = DnsOverTls?.Clone(),
            FlatteningService = FlatteningService?.Clone(),
            Delegation = Delegation?.Clone(),
            ZoneTransfer = ZoneTransfer?.Clone(),
            WildcardDns = WildcardDns?.Clone(),
            Ttl = Ttl?.Clone(),
            SecurityTxt = SecurityTxt?.Clone(),
            Robots = Robots?.Clone()
        };
    }

    public void Apply(DesiredStateProfile? overlay) {
        if (overlay == null) return;

        if (overlay.Checks != null) {
            Checks = overlay.Checks.ToArray();
        }

        if (overlay.AssessmentPolicy != null) {
            AssessmentPolicy ??= new DesiredStateAssessmentPolicy();
            AssessmentPolicy.Apply(overlay.AssessmentPolicy);
        }

        if (overlay.Dmarc != null) {
            Dmarc ??= new DesiredStateDmarcPolicy();
            Dmarc.Apply(overlay.Dmarc);
        }

        if (overlay.Spf != null) {
            Spf ??= new DesiredStateSpfPolicy();
            Spf.Apply(overlay.Spf);
        }

        if (overlay.Dkim != null) {
            Dkim ??= new DesiredStateDkimPolicy();
            Dkim.Apply(overlay.Dkim);
        }

        if (overlay.Mtasts != null) {
            Mtasts ??= new DesiredStateMtastsPolicy();
            Mtasts.Apply(overlay.Mtasts);
        }

        if (overlay.TlsRpt != null) {
            TlsRpt ??= new DesiredStateTlsRptPolicy();
            TlsRpt.Apply(overlay.TlsRpt);
        }

        if (overlay.Bimi != null) {
            Bimi ??= new DesiredStateBimiPolicy();
            Bimi.Apply(overlay.Bimi);
        }

        if (overlay.Mx != null) {
            Mx ??= new DesiredStateMxPolicy();
            Mx.Apply(overlay.Mx);
        }

        if (overlay.StartTls != null) {
            StartTls ??= new DesiredStateStartTlsPolicy();
            StartTls.Apply(overlay.StartTls);
        }

        if (overlay.SmtpTls != null) {
            SmtpTls ??= new DesiredStateMailTlsPolicy();
            SmtpTls.Apply(overlay.SmtpTls);
        }

        if (overlay.ImapTls != null) {
            ImapTls ??= new DesiredStateMailTlsPolicy();
            ImapTls.Apply(overlay.ImapTls);
        }

        if (overlay.Pop3Tls != null) {
            Pop3Tls ??= new DesiredStateMailTlsPolicy();
            Pop3Tls.Apply(overlay.Pop3Tls);
        }

        if (overlay.SmtpBanner != null) {
            SmtpBanner ??= new DesiredStateSmtpBannerPolicy();
            SmtpBanner.Apply(overlay.SmtpBanner);
        }

        if (overlay.SmtpAuth != null) {
            SmtpAuth ??= new DesiredStateSmtpAuthPolicy();
            SmtpAuth.Apply(overlay.SmtpAuth);
        }

        if (overlay.OpenRelay != null) {
            OpenRelay ??= new DesiredStateOpenRelayPolicy();
            OpenRelay.Apply(overlay.OpenRelay);
        }

        if (overlay.OpenResolver != null) {
            OpenResolver ??= new DesiredStateOpenResolverPolicy();
            OpenResolver.Apply(overlay.OpenResolver);
        }

        if (overlay.MailLatency != null) {
            MailLatency ??= new DesiredStateMailLatencyPolicy();
            MailLatency.Apply(overlay.MailLatency);
        }

        if (overlay.Autodiscover != null) {
            Autodiscover ??= new DesiredStateAutodiscoverPolicy();
            Autodiscover.Apply(overlay.Autodiscover);
        }

        if (overlay.ReverseDns != null) {
            ReverseDns ??= new DesiredStateReverseDnsPolicy();
            ReverseDns.Apply(overlay.ReverseDns);
        }

        if (overlay.FcrDns != null) {
            FcrDns ??= new DesiredStateFcrDnsPolicy();
            FcrDns.Apply(overlay.FcrDns);
        }

        if (overlay.Ns != null) {
            Ns ??= new DesiredStateNsPolicy();
            Ns.Apply(overlay.Ns);
        }

        if (overlay.DanglingCname != null) {
            DanglingCname ??= new DesiredStateDanglingCnamePolicy();
            DanglingCname.Apply(overlay.DanglingCname);
        }

        if (overlay.Caa != null) {
            Caa ??= new DesiredStateCaaPolicy();
            Caa.Apply(overlay.Caa);
        }

        if (overlay.DnsSec != null) {
            DnsSec ??= new DesiredStateDnssecPolicy();
            DnsSec.Apply(overlay.DnsSec);
        }

        if (overlay.Soa != null) {
            Soa ??= new DesiredStateSoaPolicy();
            Soa.Apply(overlay.Soa);
        }

        if (overlay.Dane != null) {
            Dane ??= new DesiredStateDanePolicy();
            Dane.Apply(overlay.Dane);
        }

        if (overlay.Dnsbl != null) {
            Dnsbl ??= new DesiredStateDnsblPolicy();
            Dnsbl.Apply(overlay.Dnsbl);
        }

        if (overlay.DnsHealth != null) {
            DnsHealth ??= new DesiredStateDnsHealthPolicy();
            DnsHealth.Apply(overlay.DnsHealth);
        }

        if (overlay.ApexAddress != null) {
            ApexAddress ??= new DesiredStateApexAddressPolicy();
            ApexAddress.Apply(overlay.ApexAddress);
        }

        if (overlay.Rpki != null) {
            Rpki ??= new DesiredStateRpkiPolicy();
            Rpki.Apply(overlay.Rpki);
        }

        if (overlay.EdnsSupport != null) {
            EdnsSupport ??= new DesiredStateEdnsSupportPolicy();
            EdnsSupport.Apply(overlay.EdnsSupport);
        }

        if (overlay.DnsOverTls != null) {
            DnsOverTls ??= new DesiredStateDnsOverTlsPolicy();
            DnsOverTls.Apply(overlay.DnsOverTls);
        }

        if (overlay.FlatteningService != null) {
            FlatteningService ??= new DesiredStateFlatteningServicePolicy();
            FlatteningService.Apply(overlay.FlatteningService);
        }

        if (overlay.Delegation != null) {
            Delegation ??= new DesiredStateDelegationPolicy();
            Delegation.Apply(overlay.Delegation);
        }

        if (overlay.ZoneTransfer != null) {
            ZoneTransfer ??= new DesiredStateZoneTransferPolicy();
            ZoneTransfer.Apply(overlay.ZoneTransfer);
        }

        if (overlay.WildcardDns != null) {
            WildcardDns ??= new DesiredStateWildcardDnsPolicy();
            WildcardDns.Apply(overlay.WildcardDns);
        }

        if (overlay.Ttl != null) {
            Ttl ??= new DesiredStateTtlPolicy();
            Ttl.Apply(overlay.Ttl);
        }

        if (overlay.SecurityTxt != null) {
            SecurityTxt ??= new DesiredStateSecurityTxtPolicy();
            SecurityTxt.Apply(overlay.SecurityTxt);
        }

        if (overlay.Robots != null) {
            Robots ??= new DesiredStateRobotsPolicy();
            Robots.Apply(overlay.Robots);
        }
    }

    public void Normalize() {
        Dmarc?.NormalizeDefaults();
        Spf?.NormalizeDefaults();
        Dkim?.NormalizeDefaults();
        Mtasts?.NormalizeDefaults();
        TlsRpt?.NormalizeDefaults();
        Bimi?.NormalizeDefaults();
        Mx?.NormalizeDefaults();
        StartTls?.NormalizeDefaults();
        SmtpTls?.NormalizeDefaults();
        ImapTls?.NormalizeDefaults();
        Pop3Tls?.NormalizeDefaults();
        SmtpBanner?.NormalizeDefaults();
        SmtpAuth?.NormalizeDefaults();
        OpenRelay?.NormalizeDefaults();
        OpenResolver?.NormalizeDefaults();
        MailLatency?.NormalizeDefaults();
        Autodiscover?.NormalizeDefaults();
        ReverseDns?.NormalizeDefaults();
        FcrDns?.NormalizeDefaults();
        Ns?.NormalizeDefaults();
        DanglingCname?.NormalizeDefaults();
        Caa?.NormalizeDefaults();
        DnsSec?.NormalizeDefaults();
        Soa?.NormalizeDefaults();
        Dane?.NormalizeDefaults();
        Dnsbl?.NormalizeDefaults();
        DnsHealth?.NormalizeDefaults();
        ApexAddress?.NormalizeDefaults();
        Rpki?.NormalizeDefaults();
        EdnsSupport?.NormalizeDefaults();
        DnsOverTls?.NormalizeDefaults();
        FlatteningService?.NormalizeDefaults();
        Delegation?.NormalizeDefaults();
        ZoneTransfer?.NormalizeDefaults();
        WildcardDns?.NormalizeDefaults();
        Ttl?.NormalizeDefaults();
        SecurityTxt?.NormalizeDefaults();
        Robots?.NormalizeDefaults();
    }
}

internal static class WildcardMatcher {
    private static readonly RegexOptions _options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private static readonly TimeSpan _timeout = TimeSpan.FromMilliseconds(250);

    private const int CacheLimit = 256;
    private static readonly object _cacheLock = new object();
    private static readonly Dictionary<string, Regex> _regexCache = new Dictionary<string, Regex>(StringComparer.Ordinal);
    private static readonly Dictionary<string, LinkedListNode<string>> _lruNodes = new Dictionary<string, LinkedListNode<string>>(StringComparer.Ordinal);
    private static readonly LinkedList<string> _lru = new LinkedList<string>();

    public static bool IsMatch(string input, string pattern) {
        if (input == null || pattern == null) {
            return false;
        }
        if (pattern == "*") {
            return true;
        }

        var regex = GetOrCreateRegex(pattern);
        if (regex == null) {
            return false;
        }

        try {
            return regex.IsMatch(input);
        } catch (RegexMatchTimeoutException) {
            return false;
        }
    }

    private static Regex? GetOrCreateRegex(string pattern) {
        if (pattern == null) return null;

        // Basic complexity bounds to reduce pathological patterns and allocations.
        // Domain wildcard patterns are typically short (<= 253 chars).
        if (pattern.Length > 512) {
            return null;
        }
        var wildcards = 0;
        for (var i = 0; i < pattern.Length; i++) {
            var ch = pattern[i];
            if (ch == '*' || ch == '?') {
                wildcards++;
                if (wildcards > 128) {
                    return null;
                }
            }
        }

        lock (_cacheLock) {
            if (_regexCache.TryGetValue(pattern, out var cached)) {
                Touch(pattern);
                return cached;
            }
        }

        string regexText;
        try {
            regexText = "^" + Regex.Escape(pattern)
                .Replace("\\*", ".*")
                .Replace("\\?", ".") + "$";
        } catch (ArgumentException) {
            return null;
        }

        Regex created;
        try {
            created = new Regex(regexText, _options, _timeout);
        } catch (ArgumentException) {
            return null;
        }

        lock (_cacheLock) {
            if (_regexCache.TryGetValue(pattern, out var existing)) {
                Touch(pattern);
                return existing;
            }

            _regexCache[pattern] = created;
            Touch(pattern);

            if (_regexCache.Count > CacheLimit) {
                EvictLeastRecentlyUsed();
            }
        }
        return created;
    }

    private static void Touch(string pattern) {
        if (pattern == null) return;

        if (_lruNodes.TryGetValue(pattern, out var node)) {
            if (node.List != null) {
                _lru.Remove(node);
            }
        } else {
            node = new LinkedListNode<string>(pattern);
            _lruNodes[pattern] = node;
        }
        _lru.AddFirst(node);
    }

    private static void EvictLeastRecentlyUsed() {
        var last = _lru.Last;
        if (last == null) return;

        var key = last.Value;
        _lru.RemoveLast();
        _lruNodes.Remove(key);
        _regexCache.Remove(key);
    }
}
