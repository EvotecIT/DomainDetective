using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using DomainDetective.Definitions;
using DomainDetective.Helpers;

namespace DomainDetective.DesiredState;

/// <summary>
/// Represents an organization-specific desired state baseline for DomainDetective checks.
/// </summary>
public sealed class DesiredStateConfiguration {
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("defaults")]
    public DesiredStateProfile Defaults { get; set; } = new DesiredStateProfile();

    [JsonPropertyName("overrides")]
    public List<DesiredStateOverride> Overrides { get; set; } = new List<DesiredStateOverride>();

    public static DesiredStateConfiguration Load(string path) {
        if (string.IsNullOrWhiteSpace(path)) {
            throw new ArgumentNullException(nameof(path));
        }
        var fullPath = Path.GetFullPath(path);
        var json = File.ReadAllText(fullPath);
        var config = JsonSerializer.Deserialize<DesiredStateConfiguration>(json, JsonOptions.Default);
        if (config == null) {
            throw new InvalidOperationException($"Failed to deserialize desired state configuration from '{fullPath}'.");
        }
        return config;
    }

    public bool RequiresMailClassification() {
        if (Overrides == null || Overrides.Count == 0) return false;
        foreach (var o in Overrides) {
            if (o?.Match?.Classifications != null && o.Match.Classifications.Length > 0) {
                return true;
            }
        }
        return false;
    }

    public DesiredStateProfile ResolveProfile(string domain, MailDomainClassificationCategory? classification = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        var effective = Defaults?.Clone() ?? new DesiredStateProfile();
        if (Overrides == null || Overrides.Count == 0) {
            effective.Normalize();
            return effective;
        }

        foreach (var o in Overrides) {
            if (o == null) continue;
            if (o.Matches(domain, classification)) {
                effective.Apply(o.Profile);
            }
        }
        effective.Normalize();
        return effective;
    }

    public static HealthCheckType[] GetRequiredChecks(DesiredStateProfile profile) {
        if (profile == null) return Array.Empty<HealthCheckType>();

        var set = new HashSet<HealthCheckType>();

        if (profile.Checks != null) {
            foreach (var c in profile.Checks) set.Add(c);
        }

        if (profile.Dmarc != null && profile.Dmarc.Enabled != false) set.Add(HealthCheckType.DMARC);
        if (profile.Spf != null && profile.Spf.Enabled != false) set.Add(HealthCheckType.SPF);
        if (profile.Dkim != null && profile.Dkim.Enabled != false) set.Add(HealthCheckType.DKIM);
        if (profile.Mtasts != null && profile.Mtasts.Enabled != false) set.Add(HealthCheckType.MTASTS);
        if (profile.TlsRpt != null && profile.TlsRpt.Enabled != false) set.Add(HealthCheckType.TLSRPT);
        if (profile.Bimi != null && profile.Bimi.Enabled != false) set.Add(HealthCheckType.BIMI);
        if (profile.Mx != null && profile.Mx.Enabled != false) set.Add(HealthCheckType.MX);
        if (profile.ReverseDns != null && profile.ReverseDns.Enabled != false) set.Add(HealthCheckType.REVERSEDNS);
        if (profile.FcrDns != null && profile.FcrDns.Enabled != false) set.Add(HealthCheckType.FCRDNS);
        if (profile.Ns != null && profile.Ns.Enabled != false) set.Add(HealthCheckType.NS);
        if (profile.DanglingCname != null && profile.DanglingCname.Enabled != false) set.Add(HealthCheckType.DANGLINGCNAME);
        if (profile.Caa != null && profile.Caa.Enabled != false) set.Add(HealthCheckType.CAA);
        if (profile.DnsSec != null && profile.DnsSec.Enabled != false) set.Add(HealthCheckType.DNSSEC);
        if (profile.Soa != null && profile.Soa.Enabled != false) set.Add(HealthCheckType.SOA);
        if (profile.Dane != null && profile.Dane.Enabled != false) set.Add(HealthCheckType.DANE);
        if (profile.Dnsbl != null && profile.Dnsbl.Enabled != false) set.Add(HealthCheckType.DNSBL);
        if (profile.DnsHealth != null && profile.DnsHealth.Enabled != false) set.Add(HealthCheckType.DNSHEALTH);
        if (profile.ApexAddress != null && profile.ApexAddress.Enabled != false) set.Add(HealthCheckType.APEXADDRESS);
        if (profile.Rpki != null && profile.Rpki.Enabled != false) set.Add(HealthCheckType.RPKI);
        if (profile.EdnsSupport != null && profile.EdnsSupport.Enabled != false) set.Add(HealthCheckType.EDNSSUPPORT);
        if (profile.DnsOverTls != null && profile.DnsOverTls.Enabled != false) set.Add(HealthCheckType.DNSOVERTLS);
        if (profile.FlatteningService != null && profile.FlatteningService.Enabled != false) set.Add(HealthCheckType.FLATTENINGSERVICE);
        if (profile.Delegation != null && profile.Delegation.Enabled != false) set.Add(HealthCheckType.DELEGATION);
        if (profile.ZoneTransfer != null && profile.ZoneTransfer.Enabled != false) set.Add(HealthCheckType.ZONETRANSFER);
        if (profile.WildcardDns != null && profile.WildcardDns.Enabled != false) set.Add(HealthCheckType.WILDCARDDNS);
        if (profile.Ttl != null && profile.Ttl.Enabled != false) set.Add(HealthCheckType.TTL);

        return set.ToArray();
    }
}

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
            Ttl = Ttl?.Clone()
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
    }

    public void Normalize() {
        Dmarc?.NormalizeDefaults();
        Spf?.NormalizeDefaults();
        Dkim?.NormalizeDefaults();
        Mtasts?.NormalizeDefaults();
        TlsRpt?.NormalizeDefaults();
        Bimi?.NormalizeDefaults();
        Mx?.NormalizeDefaults();
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
    }
}

public sealed class DesiredStateAssessmentPolicy {
    [JsonPropertyName("suppressCodes")]
    public string[]? SuppressCodes { get; set; }

    [JsonPropertyName("severityOverrides")]
    public Dictionary<string, AssessmentSeverity>? SeverityOverrides { get; set; }

    public DesiredStateAssessmentPolicy Clone() {
        return new DesiredStateAssessmentPolicy {
            SuppressCodes = SuppressCodes?.ToArray(),
            SeverityOverrides = SeverityOverrides != null
                ? new Dictionary<string, AssessmentSeverity>(SeverityOverrides, StringComparer.OrdinalIgnoreCase)
                : null
        };
    }

    public void Apply(DesiredStateAssessmentPolicy? overlay) {
        if (overlay == null) return;
        if (overlay.SuppressCodes != null) {
            SuppressCodes = overlay.SuppressCodes.ToArray();
        }
        if (overlay.SeverityOverrides != null) {
            SeverityOverrides = new Dictionary<string, AssessmentSeverity>(overlay.SeverityOverrides, StringComparer.OrdinalIgnoreCase);
        }
    }
}

public sealed class DesiredStateDmarcPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Allowed DMARC policy values (p= tag), as lowercase strings (none/quarantine/reject).</summary>
    [JsonPropertyName("allowedPolicies")]
    public string[]? AllowedPolicies { get; set; }

    /// <summary>Allowed DMARC subdomain policy values (sp= tag), as lowercase strings (none/quarantine/reject).</summary>
    [JsonPropertyName("allowedSubdomainPolicies")]
    public string[]? AllowedSubdomainPolicies { get; set; }

    /// <summary>When true, requires an explicit sp= tag to be present.</summary>
    [JsonPropertyName("requireSubdomainPolicyTag")]
    public bool? RequireSubdomainPolicyTag { get; set; }

    /// <summary>Allowed aspf values (r/s) as lowercase strings.</summary>
    [JsonPropertyName("allowedAspfAlignments")]
    public string[]? AllowedAspfAlignments { get; set; }

    /// <summary>Allowed adkim values (r/s) as lowercase strings.</summary>
    [JsonPropertyName("allowedAdkimAlignments")]
    public string[]? AllowedAdkimAlignments { get; set; }

    [JsonPropertyName("requireRua")]
    public bool? RequireRua { get; set; }

    /// <summary>Allowed domain suffixes for DMARC rua/ruf URIs (e.g., dmarc.vendor.example).</summary>
    [JsonPropertyName("allowedReportDomainSuffixes")]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    /// <summary>When true, requires external reporting domains to be authorized via _report._dmarc.</summary>
    [JsonPropertyName("requireExternalReportAuthorization")]
    public bool? RequireExternalReportAuthorization { get; set; }

    public DesiredStateDmarcPolicy Clone() {
        return new DesiredStateDmarcPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            AllowedPolicies = AllowedPolicies?.ToArray(),
            AllowedSubdomainPolicies = AllowedSubdomainPolicies?.ToArray(),
            RequireSubdomainPolicyTag = RequireSubdomainPolicyTag,
            AllowedAspfAlignments = AllowedAspfAlignments?.ToArray(),
            AllowedAdkimAlignments = AllowedAdkimAlignments?.ToArray(),
            RequireRua = RequireRua,
            AllowedReportDomainSuffixes = AllowedReportDomainSuffixes?.ToArray(),
            RequireExternalReportAuthorization = RequireExternalReportAuthorization
        };
    }

    public void Apply(DesiredStateDmarcPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.AllowedPolicies != null) AllowedPolicies = overlay.AllowedPolicies.ToArray();
        if (overlay.AllowedSubdomainPolicies != null) AllowedSubdomainPolicies = overlay.AllowedSubdomainPolicies.ToArray();
        if (overlay.RequireSubdomainPolicyTag.HasValue) RequireSubdomainPolicyTag = overlay.RequireSubdomainPolicyTag;
        if (overlay.AllowedAspfAlignments != null) AllowedAspfAlignments = overlay.AllowedAspfAlignments.ToArray();
        if (overlay.AllowedAdkimAlignments != null) AllowedAdkimAlignments = overlay.AllowedAdkimAlignments.ToArray();
        if (overlay.RequireRua.HasValue) RequireRua = overlay.RequireRua;
        if (overlay.AllowedReportDomainSuffixes != null) AllowedReportDomainSuffixes = overlay.AllowedReportDomainSuffixes.ToArray();
        if (overlay.RequireExternalReportAuthorization.HasValue) RequireExternalReportAuthorization = overlay.RequireExternalReportAuthorization;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireRua ??= true;
        RequireExternalReportAuthorization ??= true;
        RequireSubdomainPolicyTag ??= false;
    }
}

public sealed class DesiredStateSpfPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Allowed all mechanisms, as SPF syntax strings (e.g., "-all", "~all").</summary>
    [JsonPropertyName("allowedAllMechanisms")]
    public string[]? AllowedAllMechanisms { get; set; }

    [JsonPropertyName("maxDnsLookups")]
    public int? MaxDnsLookups { get; set; }

    [JsonPropertyName("requireDenyAll")]
    public bool? RequireDenyAll { get; set; }

    /// <summary>Include domains that must be present in the SPF record (top-level or resolved chain).</summary>
    [JsonPropertyName("requiredIncludeDomains")]
    public string[]? RequiredIncludeDomains { get; set; }

    /// <summary>When true, checks required include domains against the resolved include chain.</summary>
    [JsonPropertyName("matchResolvedIncludes")]
    public bool? MatchResolvedIncludes { get; set; }

    /// <summary>When true, disallows the use of the SPF ptr mechanism.</summary>
    [JsonPropertyName("disallowPtr")]
    public bool? DisallowPtr { get; set; }

    /// <summary>When true, disallows unknown mechanisms/modifiers.</summary>
    [JsonPropertyName("disallowUnknownMechanisms")]
    public bool? DisallowUnknownMechanisms { get; set; }

    /// <summary>When true, disallows the redirect= modifier.</summary>
    [JsonPropertyName("disallowRedirect")]
    public bool? DisallowRedirect { get; set; }

    /// <summary>When true, requires the redirect= modifier to be present.</summary>
    [JsonPropertyName("requireRedirect")]
    public bool? RequireRedirect { get; set; }

    /// <summary>Allowed domain suffixes for redirect= target.</summary>
    [JsonPropertyName("allowedRedirectDomainSuffixes")]
    public string[]? AllowedRedirectDomainSuffixes { get; set; }

    public DesiredStateSpfPolicy Clone() {
        return new DesiredStateSpfPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            AllowedAllMechanisms = AllowedAllMechanisms?.ToArray(),
            MaxDnsLookups = MaxDnsLookups,
            RequireDenyAll = RequireDenyAll,
            RequiredIncludeDomains = RequiredIncludeDomains?.ToArray(),
            MatchResolvedIncludes = MatchResolvedIncludes,
            DisallowPtr = DisallowPtr,
            DisallowUnknownMechanisms = DisallowUnknownMechanisms,
            DisallowRedirect = DisallowRedirect,
            RequireRedirect = RequireRedirect,
            AllowedRedirectDomainSuffixes = AllowedRedirectDomainSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateSpfPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.AllowedAllMechanisms != null) AllowedAllMechanisms = overlay.AllowedAllMechanisms.ToArray();
        if (overlay.MaxDnsLookups.HasValue) MaxDnsLookups = overlay.MaxDnsLookups;
        if (overlay.RequireDenyAll.HasValue) RequireDenyAll = overlay.RequireDenyAll;
        if (overlay.RequiredIncludeDomains != null) RequiredIncludeDomains = overlay.RequiredIncludeDomains.ToArray();
        if (overlay.MatchResolvedIncludes.HasValue) MatchResolvedIncludes = overlay.MatchResolvedIncludes;
        if (overlay.DisallowPtr.HasValue) DisallowPtr = overlay.DisallowPtr;
        if (overlay.DisallowUnknownMechanisms.HasValue) DisallowUnknownMechanisms = overlay.DisallowUnknownMechanisms;
        if (overlay.DisallowRedirect.HasValue) DisallowRedirect = overlay.DisallowRedirect;
        if (overlay.RequireRedirect.HasValue) RequireRedirect = overlay.RequireRedirect;
        if (overlay.AllowedRedirectDomainSuffixes != null) AllowedRedirectDomainSuffixes = overlay.AllowedRedirectDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireDenyAll ??= false;
        MatchResolvedIncludes ??= true;
        DisallowPtr ??= false;
        DisallowUnknownMechanisms ??= false;
        DisallowRedirect ??= false;
        RequireRedirect ??= false;
    }
}

public sealed class DesiredStateDkimPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, requires at least one DKIM selector to be analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneSelector")]
    public bool? RequireAtLeastOneSelector { get; set; }

    /// <summary>Selectors that must exist and publish DKIM records (organization-specific).</summary>
    [JsonPropertyName("requiredSelectors")]
    public string[]? RequiredSelectors { get; set; }

    /// <summary>Minimum accepted key length in bits for selectors (best-effort, RSA-focused).</summary>
    [JsonPropertyName("minKeyBits")]
    public int? MinKeyBits { get; set; }

    /// <summary>Allowed domain suffixes for selector CNAME targets (vendor-hosted DKIM).</summary>
    [JsonPropertyName("allowedCnameTargetSuffixes")]
    public string[]? AllowedCnameTargetSuffixes { get; set; }

    public DesiredStateDkimPolicy Clone() {
        return new DesiredStateDkimPolicy {
            Enabled = Enabled,
            RequireAtLeastOneSelector = RequireAtLeastOneSelector,
            RequiredSelectors = RequiredSelectors?.ToArray(),
            MinKeyBits = MinKeyBits,
            AllowedCnameTargetSuffixes = AllowedCnameTargetSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateDkimPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneSelector.HasValue) RequireAtLeastOneSelector = overlay.RequireAtLeastOneSelector;
        if (overlay.RequiredSelectors != null) RequiredSelectors = overlay.RequiredSelectors.ToArray();
        if (overlay.MinKeyBits.HasValue) MinKeyBits = overlay.MinKeyBits;
        if (overlay.AllowedCnameTargetSuffixes != null) AllowedCnameTargetSuffixes = overlay.AllowedCnameTargetSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}

public sealed class DesiredStateMtastsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireEnforce")]
    public bool? RequireEnforce { get; set; }

    /// <summary>Minimum accepted max_age value (seconds).</summary>
    [JsonPropertyName("minMaxAge")]
    public int? MinMaxAge { get; set; }

    [JsonPropertyName("requireMxAligned")]
    public bool? RequireMxAligned { get; set; }

    public DesiredStateMtastsPolicy Clone() {
        return new DesiredStateMtastsPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireEnforce = RequireEnforce,
            MinMaxAge = MinMaxAge,
            RequireMxAligned = RequireMxAligned
        };
    }

    public void Apply(DesiredStateMtastsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireEnforce.HasValue) RequireEnforce = overlay.RequireEnforce;
        if (overlay.MinMaxAge.HasValue) MinMaxAge = overlay.MinMaxAge;
        if (overlay.RequireMxAligned.HasValue) RequireMxAligned = overlay.RequireMxAligned;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}

public sealed class DesiredStateTlsRptPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireRua")]
    public bool? RequireRua { get; set; }

    [JsonPropertyName("requireValidPolicy")]
    public bool? RequireValidPolicy { get; set; }

    /// <summary>Allowed domain suffixes for TLSRPT rua endpoints (mailto domains / HTTPS hosts).</summary>
    [JsonPropertyName("allowedReportDomainSuffixes")]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    public DesiredStateTlsRptPolicy Clone() {
        return new DesiredStateTlsRptPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireRua = RequireRua,
            RequireValidPolicy = RequireValidPolicy,
            AllowedReportDomainSuffixes = AllowedReportDomainSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateTlsRptPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireRua.HasValue) RequireRua = overlay.RequireRua;
        if (overlay.RequireValidPolicy.HasValue) RequireValidPolicy = overlay.RequireValidPolicy;
        if (overlay.AllowedReportDomainSuffixes != null) AllowedReportDomainSuffixes = overlay.AllowedReportDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}

public sealed class DesiredStateBimiPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, requires the domain not to decline publishing a BIMI indicator (l= and/or a= must be present).</summary>
    [JsonPropertyName("requireIndicator")]
    public bool? RequireIndicator { get; set; }

    /// <summary>When true, requires a valid https://...svg(.svgz) location.</summary>
    [JsonPropertyName("requireValidLocation")]
    public bool? RequireValidLocation { get; set; }

    /// <summary>Allowed host suffixes for the indicator URL (vendor-hosted BIMI).</summary>
    [JsonPropertyName("allowedLocationHostSuffixes")]
    public string[]? AllowedLocationHostSuffixes { get; set; }

    /// <summary>When true, requires an authority (VMC) URL.</summary>
    [JsonPropertyName("requireAuthority")]
    public bool? RequireAuthority { get; set; }

    /// <summary>Allowed host suffixes for the authority URL (vendor-hosted VMC).</summary>
    [JsonPropertyName("allowedAuthorityHostSuffixes")]
    public string[]? AllowedAuthorityHostSuffixes { get; set; }

    /// <summary>When true, do not download the indicator SVG as part of the BIMI check.</summary>
    [JsonPropertyName("skipIndicatorDownload")]
    public bool? SkipIndicatorDownload { get; set; }

    public DesiredStateBimiPolicy Clone() {
        return new DesiredStateBimiPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireIndicator = RequireIndicator,
            RequireValidLocation = RequireValidLocation,
            AllowedLocationHostSuffixes = AllowedLocationHostSuffixes?.ToArray(),
            RequireAuthority = RequireAuthority,
            AllowedAuthorityHostSuffixes = AllowedAuthorityHostSuffixes?.ToArray(),
            SkipIndicatorDownload = SkipIndicatorDownload
        };
    }

    public void Apply(DesiredStateBimiPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireIndicator.HasValue) RequireIndicator = overlay.RequireIndicator;
        if (overlay.RequireValidLocation.HasValue) RequireValidLocation = overlay.RequireValidLocation;
        if (overlay.AllowedLocationHostSuffixes != null) AllowedLocationHostSuffixes = overlay.AllowedLocationHostSuffixes.ToArray();
        if (overlay.RequireAuthority.HasValue) RequireAuthority = overlay.RequireAuthority;
        if (overlay.AllowedAuthorityHostSuffixes != null) AllowedAuthorityHostSuffixes = overlay.AllowedAuthorityHostSuffixes.ToArray();
        if (overlay.SkipIndicatorDownload.HasValue) SkipIndicatorDownload = overlay.SkipIndicatorDownload;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        RequireIndicator ??= false;
        RequireValidLocation ??= false;
        RequireAuthority ??= false;
        SkipIndicatorDownload ??= true;
    }
}

public sealed class DesiredStateMxPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireNullMx")]
    public bool? RequireNullMx { get; set; }

    [JsonPropertyName("disallowNullMx")]
    public bool? DisallowNullMx { get; set; }

    [JsonPropertyName("requireBackupServers")]
    public bool? RequireBackupServers { get; set; }

    [JsonPropertyName("requireIpv6Supported")]
    public bool? RequireIpv6Supported { get; set; }

    /// <summary>Allowed host suffixes for MX targets (e.g., protection.outlook.com).</summary>
    [JsonPropertyName("allowedHostSuffixes")]
    public string[]? AllowedHostSuffixes { get; set; }

    [JsonPropertyName("disallowCnameTargets")]
    public bool? DisallowCnameTargets { get; set; }

    [JsonPropertyName("disallowIpTargets")]
    public bool? DisallowIpTargets { get; set; }

    [JsonPropertyName("disallowNonExistentTargets")]
    public bool? DisallowNonExistentTargets { get; set; }

    [JsonPropertyName("disallowNoAddressTargets")]
    public bool? DisallowNoAddressTargets { get; set; }

    [JsonPropertyName("disallowLocalhostTargets")]
    public bool? DisallowLocalhostTargets { get; set; }

    [JsonPropertyName("requireTtlUniform")]
    public bool? RequireTtlUniform { get; set; }

    [JsonPropertyName("requireRrsetConsistentAcrossNs")]
    public bool? RequireRrsetConsistentAcrossNs { get; set; }

    [JsonPropertyName("requireTargetAddressConsistentAcrossNs")]
    public bool? RequireTargetAddressConsistentAcrossNs { get; set; }

    public DesiredStateMxPolicy Clone() {
        return new DesiredStateMxPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireNullMx = RequireNullMx,
            DisallowNullMx = DisallowNullMx,
            RequireBackupServers = RequireBackupServers,
            RequireIpv6Supported = RequireIpv6Supported,
            AllowedHostSuffixes = AllowedHostSuffixes?.ToArray(),
            DisallowCnameTargets = DisallowCnameTargets,
            DisallowIpTargets = DisallowIpTargets,
            DisallowNonExistentTargets = DisallowNonExistentTargets,
            DisallowNoAddressTargets = DisallowNoAddressTargets,
            DisallowLocalhostTargets = DisallowLocalhostTargets,
            RequireTtlUniform = RequireTtlUniform,
            RequireRrsetConsistentAcrossNs = RequireRrsetConsistentAcrossNs,
            RequireTargetAddressConsistentAcrossNs = RequireTargetAddressConsistentAcrossNs
        };
    }

    public void Apply(DesiredStateMxPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireNullMx.HasValue) RequireNullMx = overlay.RequireNullMx;
        if (overlay.DisallowNullMx.HasValue) DisallowNullMx = overlay.DisallowNullMx;
        if (overlay.RequireBackupServers.HasValue) RequireBackupServers = overlay.RequireBackupServers;
        if (overlay.RequireIpv6Supported.HasValue) RequireIpv6Supported = overlay.RequireIpv6Supported;
        if (overlay.AllowedHostSuffixes != null) AllowedHostSuffixes = overlay.AllowedHostSuffixes.ToArray();
        if (overlay.DisallowCnameTargets.HasValue) DisallowCnameTargets = overlay.DisallowCnameTargets;
        if (overlay.DisallowIpTargets.HasValue) DisallowIpTargets = overlay.DisallowIpTargets;
        if (overlay.DisallowNonExistentTargets.HasValue) DisallowNonExistentTargets = overlay.DisallowNonExistentTargets;
        if (overlay.DisallowNoAddressTargets.HasValue) DisallowNoAddressTargets = overlay.DisallowNoAddressTargets;
        if (overlay.DisallowLocalhostTargets.HasValue) DisallowLocalhostTargets = overlay.DisallowLocalhostTargets;
        if (overlay.RequireTtlUniform.HasValue) RequireTtlUniform = overlay.RequireTtlUniform;
        if (overlay.RequireRrsetConsistentAcrossNs.HasValue) RequireRrsetConsistentAcrossNs = overlay.RequireRrsetConsistentAcrossNs;
        if (overlay.RequireTargetAddressConsistentAcrossNs.HasValue) RequireTargetAddressConsistentAcrossNs = overlay.RequireTargetAddressConsistentAcrossNs;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireNullMx ??= false;
        DisallowNullMx ??= false;
        RequireBackupServers ??= false;
        RequireIpv6Supported ??= false;
        DisallowCnameTargets ??= true;
        DisallowIpTargets ??= true;
        DisallowNonExistentTargets ??= true;
        DisallowNoAddressTargets ??= true;
        DisallowLocalhostTargets ??= true;
        RequireTtlUniform ??= false;
        RequireRrsetConsistentAcrossNs ??= false;
        RequireTargetAddressConsistentAcrossNs ??= false;
    }
}

public sealed class DesiredStateNsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireAtLeastTwo")]
    public bool? RequireAtLeastTwo { get; set; }

    [JsonPropertyName("disallowDuplicates")]
    public bool? DisallowDuplicates { get; set; }

    [JsonPropertyName("requireAllHaveAOrAaaa")]
    public bool? RequireAllHaveAOrAaaa { get; set; }

    [JsonPropertyName("disallowCnameTargets")]
    public bool? DisallowCnameTargets { get; set; }

    [JsonPropertyName("requireDiversity")]
    public bool? RequireDiversity { get; set; }

    /// <summary>Minimum distinct ASN count for authoritative name servers.</summary>
    [JsonPropertyName("minAsnDiversity")]
    public int? MinAsnDiversity { get; set; }

    /// <summary>Allowed host suffixes for authoritative NS targets (e.g., ns.provider.example).</summary>
    [JsonPropertyName("allowedHostSuffixes")]
    public string[]? AllowedHostSuffixes { get; set; }

    public DesiredStateNsPolicy Clone() {
        return new DesiredStateNsPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireAtLeastTwo = RequireAtLeastTwo,
            DisallowDuplicates = DisallowDuplicates,
            RequireAllHaveAOrAaaa = RequireAllHaveAOrAaaa,
            DisallowCnameTargets = DisallowCnameTargets,
            RequireDiversity = RequireDiversity,
            MinAsnDiversity = MinAsnDiversity,
            AllowedHostSuffixes = AllowedHostSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateNsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireAtLeastTwo.HasValue) RequireAtLeastTwo = overlay.RequireAtLeastTwo;
        if (overlay.DisallowDuplicates.HasValue) DisallowDuplicates = overlay.DisallowDuplicates;
        if (overlay.RequireAllHaveAOrAaaa.HasValue) RequireAllHaveAOrAaaa = overlay.RequireAllHaveAOrAaaa;
        if (overlay.DisallowCnameTargets.HasValue) DisallowCnameTargets = overlay.DisallowCnameTargets;
        if (overlay.RequireDiversity.HasValue) RequireDiversity = overlay.RequireDiversity;
        if (overlay.MinAsnDiversity.HasValue) MinAsnDiversity = overlay.MinAsnDiversity;
        if (overlay.AllowedHostSuffixes != null) AllowedHostSuffixes = overlay.AllowedHostSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireAtLeastTwo ??= true;
        DisallowDuplicates ??= true;
        RequireAllHaveAOrAaaa ??= true;
        DisallowCnameTargets ??= true;
        RequireDiversity ??= false;
    }
}

public sealed class DesiredStateCaaPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireValid")]
    public bool? RequireValid { get; set; }

    /// <summary>Allowed issuers for <c>issue</c> tags.</summary>
    [JsonPropertyName("allowedCertificateIssuers")]
    public string[]? AllowedCertificateIssuers { get; set; }

    /// <summary>Allowed issuers for <c>issuewild</c> tags.</summary>
    [JsonPropertyName("allowedWildcardIssuers")]
    public string[]? AllowedWildcardIssuers { get; set; }

    /// <summary>When true, requires at least one iodef reporting endpoint.</summary>
    [JsonPropertyName("requireIodef")]
    public bool? RequireIodef { get; set; }

    /// <summary>Allowed domain suffixes for iodef mailto/http reporting endpoints.</summary>
    [JsonPropertyName("allowedIodefDomainSuffixes")]
    public string[]? AllowedIodefDomainSuffixes { get; set; }

    public DesiredStateCaaPolicy Clone() {
        return new DesiredStateCaaPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireValid = RequireValid,
            AllowedCertificateIssuers = AllowedCertificateIssuers?.ToArray(),
            AllowedWildcardIssuers = AllowedWildcardIssuers?.ToArray(),
            RequireIodef = RequireIodef,
            AllowedIodefDomainSuffixes = AllowedIodefDomainSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateCaaPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireValid.HasValue) RequireValid = overlay.RequireValid;
        if (overlay.AllowedCertificateIssuers != null) AllowedCertificateIssuers = overlay.AllowedCertificateIssuers.ToArray();
        if (overlay.AllowedWildcardIssuers != null) AllowedWildcardIssuers = overlay.AllowedWildcardIssuers.ToArray();
        if (overlay.RequireIodef.HasValue) RequireIodef = overlay.RequireIodef;
        if (overlay.AllowedIodefDomainSuffixes != null) AllowedIodefDomainSuffixes = overlay.AllowedIodefDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        RequireValid ??= true;
        RequireIodef ??= false;
    }
}

internal static class WildcardMatcher {
    public static bool IsMatch(string input, string pattern) {
        if (input == null || pattern == null) return false;
        if (pattern == "*") return true;
        var regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(
            input,
            regex,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    }
}
