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
public sealed partial class DesiredStateConfiguration {
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("defaults")]
    public DesiredStateProfile Defaults { get; set; } = new DesiredStateProfile();

    [JsonPropertyName("overrides")]
    public List<DesiredStateOverride> Overrides { get; set; } = new List<DesiredStateOverride>();

    public static DesiredStateConfiguration Load(string path) {
        if (path == null) {
            throw new ArgumentNullException(nameof(path));
        }
        if (path.Trim().Length == 0) {
            throw new ArgumentException("Path cannot be empty or whitespace.", nameof(path));
        }
        var fullPath = Path.GetFullPath(path);
        var json = File.ReadAllText(fullPath);
        var config = JsonSerializer.Deserialize<DesiredStateConfiguration>(json, JsonOptions.Default);
        if (config == null) {
            throw new InvalidOperationException($"Failed to deserialize desired state configuration from '{fullPath}'.");
        }
        if (config.Version < 1) {
            throw new InvalidOperationException($"Desired state configuration version must be >= 1 (found {config.Version}) in '{fullPath}'.");
        }

        if (config.Defaults == null) {
            config.Defaults = new DesiredStateProfile();
        }
        if (config.Overrides == null) {
            config.Overrides = new List<DesiredStateOverride>();
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
        if (domain == null) {
            throw new ArgumentNullException(nameof(domain));
        }
        if (domain.Trim().Length == 0) {
            throw new ArgumentException("Domain cannot be empty or whitespace.", nameof(domain));
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
        if (profile.StartTls != null && profile.StartTls.Enabled != false) set.Add(HealthCheckType.STARTTLS);
        if (profile.SmtpTls != null && profile.SmtpTls.Enabled != false) set.Add(HealthCheckType.SMTPTLS);
        if (profile.ImapTls != null && profile.ImapTls.Enabled != false) set.Add(HealthCheckType.IMAPTLS);
        if (profile.Pop3Tls != null && profile.Pop3Tls.Enabled != false) set.Add(HealthCheckType.POP3TLS);
        if (profile.SmtpBanner != null && profile.SmtpBanner.Enabled != false) set.Add(HealthCheckType.SMTPBANNER);
        if (profile.SmtpAuth != null && profile.SmtpAuth.Enabled != false) set.Add(HealthCheckType.SMTPAUTH);
        if (profile.OpenRelay != null && profile.OpenRelay.Enabled != false) set.Add(HealthCheckType.OPENRELAY);
        if (profile.OpenResolver != null && profile.OpenResolver.Enabled != false) set.Add(HealthCheckType.OPENRESOLVER);
        if (profile.MailLatency != null && profile.MailLatency.Enabled != false) set.Add(HealthCheckType.MAILLATENCY);
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
        if (profile.Autodiscover != null && profile.Autodiscover.Enabled != false) set.Add(HealthCheckType.AUTODISCOVER);
        if (profile.SecurityTxt != null && profile.SecurityTxt.Enabled != false) set.Add(HealthCheckType.SECURITYTXT);
        if (profile.Robots != null && profile.Robots.Enabled != false) set.Add(HealthCheckType.ROBOTS);

        return set.ToArray();
    }
}
