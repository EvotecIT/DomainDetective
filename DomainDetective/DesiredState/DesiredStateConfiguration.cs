using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DomainDetective.Definitions;
using DomainDetective.Helpers;

namespace DomainDetective.DesiredState;

/// <summary>
/// Represents an organization-specific desired state baseline for DomainDetective checks.
/// </summary>
public sealed partial class DesiredStateConfiguration {
    /// <summary>Represents the supported version value.</summary>
    public const int SupportedVersion = 1;

    /// <summary>Gets or sets the schema value.</summary>
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    /// <summary>Gets or sets the version value.</summary>
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    /// <summary>Gets or sets the mode value.</summary>
    [JsonPropertyName("mode")]
    public DesiredStateMode Mode { get; set; } = DesiredStateMode.HybridSplit;

    /// <summary>Gets or sets the best practices value.</summary>
    [JsonPropertyName("bestPractices")]
    public DesiredStateBestPracticeSettings BestPractices { get; set; } = new DesiredStateBestPracticeSettings();

    /// <summary>Gets or sets the defaults value.</summary>
    [JsonPropertyName("defaults")]
    public DesiredStateProfile Defaults { get; set; } = new DesiredStateProfile();

    /// <summary>Gets or sets the overrides value.</summary>
    [JsonPropertyName("overrides")]
    public List<DesiredStateOverride> Overrides { get; set; } = new List<DesiredStateOverride>();

    /// <summary>Executes the load operation.</summary>
    public static DesiredStateConfiguration Load(string path) {
        if (string.IsNullOrWhiteSpace(path)) {
            throw new ArgumentException("Path cannot be empty or whitespace.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)) {
            throw new FileNotFoundException($"Desired state configuration file not found: '{fullPath}'.", fullPath);
        }

        // Safety: prevent accidental loading of huge files (can cause excessive allocations on deserialization).
        // Desired state configurations are typically tiny; keep a conservative upper bound to avoid accidental DoS.
        const long maxBytes = 1L * 1024L * 1024L;
        var fileInfo = new FileInfo(fullPath);
        if (fileInfo.Length > maxBytes) {
            throw new InvalidOperationException($"Desired state configuration file is too large ({fileInfo.Length} bytes > {maxBytes} bytes): '{fullPath}'.");
        }

        string json;
        try {
            json = File.ReadAllText(fullPath, Encoding.UTF8);
        } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) {
            throw new IOException($"Failed to read desired state configuration file: '{fullPath}'.", ex);
        }

        DesiredStateConfiguration config;
        config = JsonSerializer.Deserialize<DesiredStateConfiguration>(json, JsonOptions.Default)
                 ?? throw new InvalidOperationException($"Failed to deserialize desired state configuration from '{fullPath}'.");

        if (config.Version < 1) {
            throw new InvalidOperationException($"Desired state configuration version must be >= 1 (found {config.Version}) in '{fullPath}'.");
        }
        if (config.Version > SupportedVersion) {
            throw new InvalidOperationException($"Desired state configuration version {config.Version} is newer than supported version {SupportedVersion} in '{fullPath}'.");
        }

        if (config.Defaults == null) {
            config.Defaults = new DesiredStateProfile();
        }
        if (config.BestPractices == null) {
            config.BestPractices = new DesiredStateBestPracticeSettings();
        }
        if (config.Overrides == null) {
            config.Overrides = new List<DesiredStateOverride>();
        }
        return config;
    }

    /// <summary>Executes the requires mail classification operation.</summary>
    public bool RequiresMailClassification() {
        if (Overrides == null || Overrides.Count == 0) return false;
        foreach (var o in Overrides) {
            if (o?.Match?.Classifications != null && o.Match.Classifications.Length > 0) {
                return true;
            }
        }
        return false;
    }

    /// <summary>Executes the resolve profile operation.</summary>
    public DesiredStateProfile ResolveProfile(string domain, MailDomainClassificationCategory? classification = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
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

    /// <summary>Gets required checks.</summary>
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

    /// <summary>Gets checks to run.</summary>
    public HealthCheckType[] GetChecksToRun(DesiredStateProfile profile, DesiredStateMode mode) {
        return GetChecksToRun(profile, mode, BestPractices);
    }

    /// <summary>Gets checks to run.</summary>
    public static HealthCheckType[] GetChecksToRun(DesiredStateProfile profile, DesiredStateMode mode, DesiredStateBestPracticeSettings? bestPractices = null) {
        if (profile == null) return Array.Empty<HealthCheckType>();
        var required = GetRequiredChecks(profile);
        if (mode != DesiredStateMode.BestPracticesForUnspecified) {
            return required;
        }

        var set = new HashSet<HealthCheckType>(required);
        var bestChecks = bestPractices?.ResolveChecks() ?? DesiredStateBestPractices.RecommendedChecks;
        foreach (var check in bestChecks) {
            set.Add(check);
        }
        return set.ToArray();
    }
}
